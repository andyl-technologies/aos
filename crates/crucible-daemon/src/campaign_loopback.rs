//! Versioned Unix-stream transport for the user-facing campaign service.
//!
//! The protocol contains only bounded canonical component messages:
//!
//! ```text
//! CampaignLoopbackFrameV21 = magic[8] | kind:u8 | reserved[3] |
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
//!       25 (QueryCampaignFrontierResponseV1) |
//!       26 (GetCampaignFrontierObjectRequestV1) |
//!       27 (GetCampaignFrontierObjectResponseV1) |
//!       28 (PinCampaignRequestV1) |
//!       29 (PinCampaignResponseV1) |
//!       30 (QueryCampaignFindingsRequestV1) |
//!       31 (QueryCampaignFindingsResponseV1) |
//!       32 (GetCampaignFindingObjectRequestV1) |
//!       33 (GetCampaignFindingObjectResponseV1) |
//!       34 (ExplainCampaignAttemptRequestV1) |
//!       35 (ExplainCampaignAttemptResponseV2) |
//!       36 (GetCampaignPlannerRankingsRequestV1) |
//!       37 (GetCampaignPlannerRankingsResponseV2) |
//!       38 (ListCampaignsRequestV1) |
//!       39 (ListCampaignsResponseV1) |
//!       40 (AttachCampaignRuntimeRequestV1) |
//!       41 (AttachCampaignRuntimeResponseV1) |
//!       42 (GetCampaignStatusRequestV1) |
//!       43 (GetCampaignStatusResponseV1) |
//!       44 (SubmitCampaignDiscoveryRequestV1) |
//!       45 (SubmitCampaignDiscoveryResponseV1) |
//!       46 (QueryCampaignFindingOccurrencesRequestV1) |
//!       47 (QueryCampaignFindingOccurrencesResponseV1) |
//!       48 (GetCampaignFindingOccurrenceObjectRequestV1) |
//!       49 (GetCampaignFindingOccurrenceObjectResponseV1) |
//!       50 (QueryCampaignReportRequestV1) |
//!       51 (QueryCampaignReportResponseV1) |
//!       52 (GetCampaignFindingTriageReplaySegmentRequestV1) |
//!       53 (GetCampaignFindingTriageReplaySegmentResponseV1) |
//!       54 (OpenCampaignDebugSessionRequestV1) |
//!       55 (OpenCampaignDebugSessionResponseV1)
//! magic = "CRUCCS21"
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

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::Duration;

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, CampaignAuthorizationError,
    CampaignCodecError, CampaignFindingOccurrenceService, CampaignName,
    CampaignOperationalStatusProvider, CampaignPrincipal, CampaignPrincipalAuthorizer,
    CampaignRepository, CampaignService, CampaignServiceErrorResponse, CampaignServiceFailure,
    CampaignServiceFailureSource, CampaignServiceOperation, CreateCampaignRequest,
    CreateCampaignResponse, DeriveCampaignRequest, DeriveCampaignResponse,
    ExplainCampaignAttemptRequest, ExplainCampaignAttemptResponse, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFindingOccurrenceObjectRequest,
    GetCampaignFindingOccurrenceObjectResponse, GetCampaignFindingTriageReplaySegmentRequest,
    GetCampaignFindingTriageReplaySegmentResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignPlannerRankingsRequest,
    GetCampaignPlannerRankingsResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, GetCampaignStatusRequest,
    GetCampaignStatusResponse, ListCampaignsRequest, ListCampaignsResponse, PinCampaignRequest,
    PinCampaignResponse, QueryCampaignChoicesRequest, QueryCampaignChoicesResponse,
    QueryCampaignFindingOccurrencesRequest, QueryCampaignFindingOccurrencesResponse,
    QueryCampaignFindingsRequest, QueryCampaignFindingsResponse, QueryCampaignFrontierRequest,
    QueryCampaignFrontierResponse, QueryCampaignGraphRequest, QueryCampaignGraphResponse,
    QueryCampaignReportRequest, QueryCampaignReportResponse, RepositoryCampaignService,
    SubmitCampaignBranchRequest, SubmitCampaignBranchResponse, SubmitCampaignDiscoveryRequest,
    SubmitCampaignDiscoveryResponse, WatchCampaignRequest, WatchCampaignResponse,
};

use crate::campaign_diagnostics::route_campaign_service_diagnostic;
use crate::{
    AttachCampaignRuntimeRequest, AttachCampaignRuntimeResponse, CampaignDebugControlService,
    CampaignRuntimeControlService, CampaignServiceDiagnostic, CampaignServiceDiagnosticSink,
    OpenCampaignDebugSessionRequest, OpenCampaignDebugSessionResponse,
};

mod server;
pub(crate) use server::{
    CampaignConnectionControls,
    serve_authenticated_repository_campaign_connection_with_controls_limits,
};

mod transport;
#[cfg(test)]
use transport::read_frame;
pub use transport::{
    LoopbackCampaignProtocolError, LoopbackCampaignServerError, LoopbackCampaignServiceError,
};
use transport::{configure_stream, read_frame_any, validate_timeouts, write_frame};

const FRAME_MAGIC: &[u8; 8] = b"CRUCCS21";
const FRAME_HEADER_BYTES: usize = 16;
const GET_CAMPAIGN_REQUEST_KIND: u8 = 1;
const GET_CAMPAIGN_RESPONSE_KIND: u8 = 2;
const APPLY_COMMAND_REQUEST_KIND: u8 = 3;
const APPLY_COMMAND_RESPONSE_KIND: u8 = 4;
const SUBMIT_BRANCH_REQUEST_KIND: u8 = 5;
const SUBMIT_BRANCH_RESPONSE_KIND: u8 = 6;
const SERVICE_ERROR_RESPONSE_KIND: u8 = 7;
const OPEN_CAMPAIGN_DEBUG_SESSION_REQUEST_KIND: u8 = 54;
const OPEN_CAMPAIGN_DEBUG_SESSION_RESPONSE_KIND: u8 = 55;
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
const GET_CAMPAIGN_FRONTIER_OBJECT_REQUEST_KIND: u8 = 26;
const GET_CAMPAIGN_FRONTIER_OBJECT_RESPONSE_KIND: u8 = 27;
const PIN_CAMPAIGN_REQUEST_KIND: u8 = 28;
const PIN_CAMPAIGN_RESPONSE_KIND: u8 = 29;
const QUERY_CAMPAIGN_FINDINGS_REQUEST_KIND: u8 = 30;
const QUERY_CAMPAIGN_FINDINGS_RESPONSE_KIND: u8 = 31;
const GET_CAMPAIGN_FINDING_OBJECT_REQUEST_KIND: u8 = 32;
const GET_CAMPAIGN_FINDING_OBJECT_RESPONSE_KIND: u8 = 33;
const EXPLAIN_CAMPAIGN_ATTEMPT_REQUEST_KIND: u8 = 34;
const EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_KIND: u8 = 35;
const GET_CAMPAIGN_PLANNER_RANKINGS_REQUEST_KIND: u8 = 36;
const GET_CAMPAIGN_PLANNER_RANKINGS_RESPONSE_KIND: u8 = 37;
const LIST_CAMPAIGNS_REQUEST_KIND: u8 = 38;
const LIST_CAMPAIGNS_RESPONSE_KIND: u8 = 39;
const ATTACH_CAMPAIGN_RUNTIME_REQUEST_KIND: u8 = 40;
const ATTACH_CAMPAIGN_RUNTIME_RESPONSE_KIND: u8 = 41;
const GET_CAMPAIGN_STATUS_REQUEST_KIND: u8 = 42;
const GET_CAMPAIGN_STATUS_RESPONSE_KIND: u8 = 43;
const SUBMIT_DISCOVERY_REQUEST_KIND: u8 = 44;
const SUBMIT_DISCOVERY_RESPONSE_KIND: u8 = 45;
const QUERY_CAMPAIGN_FINDING_OCCURRENCES_REQUEST_KIND: u8 = 46;
const QUERY_CAMPAIGN_FINDING_OCCURRENCES_RESPONSE_KIND: u8 = 47;
const GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND: u8 = 48;
const GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_RESPONSE_KIND: u8 = 49;
const QUERY_CAMPAIGN_REPORT_REQUEST_KIND: u8 = 50;
const QUERY_CAMPAIGN_REPORT_RESPONSE_KIND: u8 = 51;
const GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_REQUEST_KIND: u8 = 52;
const GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_RESPONSE_KIND: u8 = 53;
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub(crate) const DEFAULT_CAMPAIGN_REQUESTS_PER_CONNECTION: usize = 4_096;
/// Maximum complete requests served by one campaign connection incarnation.
pub const MAX_CAMPAIGN_REQUESTS_PER_CONNECTION: usize = 65_536;

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

    /// Requests one authenticated operational campaign-runtime attachment.
    ///
    /// This operation shares campaign framing, peer authentication, policy,
    /// request binding, deadlines, and connection poisoning, but remains
    /// outside the semantic [`CampaignService`] trait because its executor
    /// path is daemon deployment state.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackCampaignServiceError`] for a stable remote failure or
    /// any framing, codec, request-binding, deadline, or connection failure.
    pub fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, LoopbackCampaignServiceError> {
        self.exchange(
            ATTACH_CAMPAIGN_RUNTIME_REQUEST_KIND,
            ATTACH_CAMPAIGN_RUNTIME_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = AttachCampaignRuntimeResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_attach_campaign_runtime,
        )
    }

    /// Opens one authenticated exclusive read-only campaign debug session.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackCampaignServiceError`] for a stable remote failure or
    /// any framing, codec, request-binding, deadline, or connection failure.
    pub fn open_campaign_debug_session(
        &self,
        request: &OpenCampaignDebugSessionRequest,
    ) -> Result<OpenCampaignDebugSessionResponse, LoopbackCampaignServiceError> {
        self.exchange(
            OPEN_CAMPAIGN_DEBUG_SESSION_REQUEST_KIND,
            OPEN_CAMPAIGN_DEBUG_SESSION_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = OpenCampaignDebugSessionResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_debug_campaign,
        )
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

    fn list_campaigns(
        &self,
        request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error> {
        self.exchange(
            LIST_CAMPAIGNS_REQUEST_KIND,
            LIST_CAMPAIGNS_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = ListCampaignsResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            CampaignServiceFailure::validate_for_list_campaigns,
        )
    }

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

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_STATUS_REQUEST_KIND,
            GET_CAMPAIGN_STATUS_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignStatusResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_status(request.snapshot()),
        )
    }

    fn query_campaign_report(
        &self,
        request: &QueryCampaignReportRequest,
    ) -> Result<QueryCampaignReportResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_REPORT_REQUEST_KIND,
            QUERY_CAMPAIGN_REPORT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = QueryCampaignReportResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_report(request.snapshot()),
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

    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_FINDINGS_REQUEST_KIND,
            QUERY_CAMPAIGN_FINDINGS_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = QueryCampaignFindingsResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_findings(request.snapshot()),
        )
    }

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_FINDING_OBJECT_REQUEST_KIND,
            GET_CAMPAIGN_FINDING_OBJECT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignFindingObjectResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_finding_object(request.snapshot()),
        )
    }

    fn explain_campaign_attempt(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        self.exchange(
            EXPLAIN_CAMPAIGN_ATTEMPT_REQUEST_KIND,
            EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = ExplainCampaignAttemptResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_explain_campaign_attempt(request.snapshot()),
        )
    }

    fn get_campaign_planner_rankings(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_PLANNER_RANKINGS_REQUEST_KIND,
            GET_CAMPAIGN_PLANNER_RANKINGS_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignPlannerRankingsResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_planner_rankings(request.snapshot()),
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

    fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_FRONTIER_OBJECT_REQUEST_KIND,
            GET_CAMPAIGN_FRONTIER_OBJECT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = GetCampaignFrontierObjectResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_get_campaign_frontier_object(request.snapshot()),
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

    fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        self.exchange(
            PIN_CAMPAIGN_REQUEST_KIND,
            PIN_CAMPAIGN_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = PinCampaignResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_pin_campaign(request.command().expected_snapshot),
        )
    }

    fn submit_discovery_request(
        &self,
        request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        self.exchange(
            SUBMIT_DISCOVERY_REQUEST_KIND,
            SUBMIT_DISCOVERY_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response = SubmitCampaignDiscoveryResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| {
                failure.validate_for_submit_discovery_request(request.command().expected_snapshot)
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

impl CampaignFindingOccurrenceService for LoopbackCampaignService {
    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, Self::Error> {
        self.exchange(
            QUERY_CAMPAIGN_FINDING_OCCURRENCES_REQUEST_KIND,
            QUERY_CAMPAIGN_FINDING_OCCURRENCES_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response =
                    QueryCampaignFindingOccurrencesResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| failure.validate_for_query_campaign_finding_occurrences(request.snapshot()),
        )
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND,
            GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response =
                    GetCampaignFindingOccurrenceObjectResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| {
                failure.validate_for_get_campaign_finding_occurrence_object(request.snapshot())
            },
        )
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
        self.exchange(
            GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_REQUEST_KIND,
            GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_RESPONSE_KIND,
            request.request_digest(),
            &request.canonical_bytes(),
            |response| {
                let response =
                    GetCampaignFindingTriageReplaySegmentResponse::from_canonical_bytes(response)?;
                response.validate_for(request)?;
                Ok(response)
            },
            |failure| {
                failure.validate_for_get_campaign_finding_triage_replay_segment(request.snapshot())
            },
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
    #[cfg(test)]
    pub(crate) const fn for_test(process_id: i32, user_id: u32, group_id: u32) -> Self {
        Self {
            process_id,
            user_id,
            group_id,
        }
    }

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
/// claim the exact resolved principal. Production resolvers must be bounded,
/// nonblocking lookups over immutable local policy; external identity I/O does
/// not belong inside a connection worker.
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
    fn authorize_all_campaigns(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        request_digest: crucible_campaign::CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if principal != &self.principal {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        self.inner
            .authorize_all_campaigns(principal, operation, request_digest)
    }

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

trait RuntimeControlDispatch {
    fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, CampaignServiceFailure>;
}

trait DebugControlDispatch {
    fn open_campaign_debug_session(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure>;
}

struct AuthorizedDebugControlDispatch<'a, A: ?Sized> {
    principal: &'a CampaignPrincipal,
    authorizer: &'a A,
    service: Option<&'a dyn CampaignDebugControlService>,
}

impl<A> DebugControlDispatch for AuthorizedDebugControlDispatch<'_, A>
where
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    fn open_campaign_debug_session(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure> {
        if request.principal() != self.principal {
            return Err(CampaignServiceFailure::Unauthorized);
        }
        self.authorizer
            .authorize(
                request.principal(),
                CampaignServiceOperation::DebugCampaign,
                request.campaign(),
                request.request_digest(),
            )
            .map_err(|error| match error {
                CampaignAuthorizationError::Unauthorized => CampaignServiceFailure::Unauthorized,
                CampaignAuthorizationError::Unavailable => {
                    CampaignServiceFailure::AuthorizationUnavailable
                }
            })?;
        self.service
            .ok_or(CampaignServiceFailure::Unavailable)?
            .open_campaign_debug_session(request, finding)
    }
}

struct AuthorizedRuntimeControlDispatch<'a, A: ?Sized> {
    principal: &'a CampaignPrincipal,
    authorizer: &'a A,
    service: Option<&'a dyn CampaignRuntimeControlService>,
}

impl<A> RuntimeControlDispatch for AuthorizedRuntimeControlDispatch<'_, A>
where
    A: CampaignPrincipalAuthorizer + ?Sized,
{
    fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, CampaignServiceFailure> {
        if request.principal() != self.principal {
            return Err(CampaignServiceFailure::Unauthorized);
        }
        self.authorizer
            .authorize(
                request.principal(),
                CampaignServiceOperation::AttachCampaignRuntime,
                request.campaign(),
                request.request_digest(),
            )
            .map_err(|error| match error {
                CampaignAuthorizationError::Unauthorized => CampaignServiceFailure::Unauthorized,
                CampaignAuthorizationError::Unavailable => {
                    CampaignServiceFailure::AuthorizationUnavailable
                }
            })?;
        self.service
            .ok_or(CampaignServiceFailure::Unavailable)?
            .attach_campaign_runtime(request)
    }
}

#[cfg(test)]
fn serve_loopback_campaign_once<S>(
    stream: &mut UnixStream,
    service: &S,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService + CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    serve_loopback_campaign_once_with_timeouts(stream, service, LoopbackCampaignTimeouts::default())
}

#[cfg(test)]
fn serve_loopback_campaign_once_with_timeouts<S>(
    stream: &mut UnixStream,
    service: &S,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService + CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    let result =
        serve_loopback_campaign_inner_with_controls(stream, service, None, None, None, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_campaign_inner_with_controls<S>(
    stream: &mut UnixStream,
    service: &S,
    runtime_control: Option<&dyn RuntimeControlDispatch>,
    debug_control: Option<&dyn DebugControlDispatch>,
    diagnostics: Option<&dyn CampaignServiceDiagnosticSink>,
    timeouts: LoopbackCampaignTimeouts,
) -> Result<(), LoopbackCampaignServerError>
where
    S: CampaignService + CampaignFindingOccurrenceService,
    S::Error: CampaignServiceFailureSource,
{
    configure_stream(stream, timeouts)?;
    let (kind, body) = read_frame_any(stream, timeouts.read)?;
    let (response_kind, response) = match kind {
        OPEN_CAMPAIGN_DEBUG_SESSION_REQUEST_KIND => {
            let request = OpenCampaignDebugSessionRequest::from_canonical_bytes(&body)?;
            let debug_control =
                debug_control.ok_or(LoopbackCampaignProtocolError::InvalidFrame {
                    reason: "debug-control-unavailable",
                })?;
            let finding_request = GetCampaignFindingObjectRequest::new(
                request.principal().clone(),
                request.campaign().clone(),
                request.snapshot(),
                request.finding(),
                crucible_campaign::CampaignFindingObjectKind::Reproduction,
            )?;
            match service.get_campaign_finding_object(&finding_request) {
                Ok(finding) => {
                    finding.validate_for(&finding_request)?;
                    match debug_control.open_campaign_debug_session(&request, finding) {
                        Ok(response) => {
                            response.validate_for(&request)?;
                            (
                                OPEN_CAMPAIGN_DEBUG_SESSION_RESPONSE_KIND,
                                response.canonical_bytes(),
                            )
                        }
                        Err(failure) => {
                            failure.validate_for_debug_campaign()?;
                            service_error_response(request.request_digest(), &failure)?
                        }
                    }
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    failure.validate_for_get_campaign_finding_object(request.snapshot())?;
                    service_error_response(request.request_digest(), &failure)?
                }
            }
        }
        ATTACH_CAMPAIGN_RUNTIME_REQUEST_KIND => {
            let request = AttachCampaignRuntimeRequest::from_canonical_bytes(&body)?;
            let runtime_control =
                runtime_control.ok_or(LoopbackCampaignProtocolError::InvalidFrame {
                    reason: "runtime-control-unavailable",
                })?;
            match runtime_control.attach_campaign_runtime(&request) {
                Ok(response) => {
                    if response.validate_for(&request).is_err() {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            CampaignCodecError::InvalidValue {
                                reason: "runtime attachment response basis mismatch",
                            },
                            timeouts.write,
                        );
                    }
                    (
                        ATTACH_CAMPAIGN_RUNTIME_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(failure) => {
                    if let Err(error) = failure.validate_for_attach_campaign_runtime() {
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
        LIST_CAMPAIGNS_REQUEST_KIND => {
            let request = ListCampaignsRequest::from_canonical_bytes(&body)?;
            match service.list_campaigns(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (LIST_CAMPAIGNS_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_list_campaigns() {
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
        GET_CAMPAIGN_STATUS_REQUEST_KIND => {
            let request = GetCampaignStatusRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_status(&request) {
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
                        GET_CAMPAIGN_STATUS_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure.validate_for_get_campaign_status(request.snapshot())
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
        QUERY_CAMPAIGN_REPORT_REQUEST_KIND => {
            let request = QueryCampaignReportRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_report(&request) {
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
                        QUERY_CAMPAIGN_REPORT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_report(request.snapshot())
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
        QUERY_CAMPAIGN_FINDINGS_REQUEST_KIND => {
            let request = QueryCampaignFindingsRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_findings(&request) {
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
                        QUERY_CAMPAIGN_FINDINGS_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_findings(request.snapshot())
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
        QUERY_CAMPAIGN_FINDING_OCCURRENCES_REQUEST_KIND => {
            let request = QueryCampaignFindingOccurrencesRequest::from_canonical_bytes(&body)?;
            match service.query_campaign_finding_occurrences(&request) {
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
                        QUERY_CAMPAIGN_FINDING_OCCURRENCES_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_query_campaign_finding_occurrences(request.snapshot())
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
        GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND => {
            let request = GetCampaignFindingOccurrenceObjectRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_finding_occurrence_object(&request) {
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
                        GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure
                        .validate_for_get_campaign_finding_occurrence_object(request.snapshot())
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
        GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_REQUEST_KIND => {
            let request =
                GetCampaignFindingTriageReplaySegmentRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_finding_triage_replay_segment(&request) {
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
                        GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure
                        .validate_for_get_campaign_finding_triage_replay_segment(request.snapshot())
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
        GET_CAMPAIGN_FINDING_OBJECT_REQUEST_KIND => {
            let request = GetCampaignFindingObjectRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_finding_object(&request) {
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
                        GET_CAMPAIGN_FINDING_OBJECT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_get_campaign_finding_object(request.snapshot())
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
        EXPLAIN_CAMPAIGN_ATTEMPT_REQUEST_KIND => {
            let request = ExplainCampaignAttemptRequest::from_canonical_bytes(&body)?;
            match service.explain_campaign_attempt(&request) {
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
                        EXPLAIN_CAMPAIGN_ATTEMPT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_explain_campaign_attempt(request.snapshot())
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
        GET_CAMPAIGN_PLANNER_RANKINGS_REQUEST_KIND => {
            let request = GetCampaignPlannerRankingsRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_planner_rankings(&request) {
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
                        GET_CAMPAIGN_PLANNER_RANKINGS_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_get_campaign_planner_rankings(request.snapshot())
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
        GET_CAMPAIGN_FRONTIER_OBJECT_REQUEST_KIND => {
            let request = GetCampaignFrontierObjectRequest::from_canonical_bytes(&body)?;
            match service.get_campaign_frontier_object(&request) {
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
                        GET_CAMPAIGN_FRONTIER_OBJECT_RESPONSE_KIND,
                        response.canonical_bytes(),
                    )
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_get_campaign_frontier_object(request.snapshot())
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
        PIN_CAMPAIGN_REQUEST_KIND => {
            let request = PinCampaignRequest::from_canonical_bytes(&body)?;
            match service.pin_campaign(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (PIN_CAMPAIGN_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) =
                        failure.validate_for_pin_campaign(request.command().expected_snapshot)
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
        SUBMIT_DISCOVERY_REQUEST_KIND => {
            let request = SubmitCampaignDiscoveryRequest::from_canonical_bytes(&body)?;
            match service.submit_discovery_request(&request) {
                Ok(response) => {
                    if let Err(error) = response.validate_for(&request) {
                        return reject_invalid_service_response(
                            stream,
                            request.request_digest(),
                            error,
                            timeouts.write,
                        );
                    }
                    (SUBMIT_DISCOVERY_RESPONSE_KIND, response.canonical_bytes())
                }
                Err(error) => {
                    let failure = error.campaign_service_failure();
                    if let Err(error) = failure
                        .validate_for_submit_discovery_request(request.command().expected_snapshot)
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
    if response_kind == SERVICE_ERROR_RESPONSE_KIND {
        let error = CampaignServiceErrorResponse::from_canonical_bytes(&response)?;
        let operation = campaign_operation_for_request_kind(kind).ok_or(
            LoopbackCampaignProtocolError::InvalidFrame {
                reason: "unroutable-campaign-service-error",
            },
        )?;
        if let Some(sink) = diagnostics {
            route_campaign_service_diagnostic(
                Some(sink),
                CampaignServiceDiagnostic::RequestFailure {
                    operation,
                    request_digest: error.request_digest(),
                    failure: error.failure(),
                },
            );
        }
    }
    write_frame(stream, response_kind, &response, timeouts.write)?;
    Ok(())
}

fn campaign_operation_for_request_kind(kind: u8) -> Option<CampaignServiceOperation> {
    match kind {
        LIST_CAMPAIGNS_REQUEST_KIND => Some(CampaignServiceOperation::ListCampaigns),
        CREATE_CAMPAIGN_REQUEST_KIND => Some(CampaignServiceOperation::CreateCampaign),
        DERIVE_CAMPAIGN_REQUEST_KIND => Some(CampaignServiceOperation::DeriveCampaign),
        GET_CAMPAIGN_REQUEST_KIND => Some(CampaignServiceOperation::GetCampaign),
        GET_CAMPAIGN_STATUS_REQUEST_KIND => Some(CampaignServiceOperation::GetCampaignStatus),
        GET_CAMPAIGN_SNAPSHOT_REQUEST_KIND => Some(CampaignServiceOperation::GetCampaignSnapshot),
        WATCH_CAMPAIGN_REQUEST_KIND => Some(CampaignServiceOperation::WatchCampaign),
        QUERY_CAMPAIGN_GRAPH_REQUEST_KIND => Some(CampaignServiceOperation::QueryCampaignGraph),
        GET_CAMPAIGN_GRAPH_OBJECT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignGraphObject)
        }
        QUERY_CAMPAIGN_CHOICES_REQUEST_KIND => Some(CampaignServiceOperation::QueryCampaignChoices),
        QUERY_CAMPAIGN_FRONTIER_REQUEST_KIND => {
            Some(CampaignServiceOperation::QueryCampaignFrontier)
        }
        QUERY_CAMPAIGN_REPORT_REQUEST_KIND => Some(CampaignServiceOperation::QueryCampaignReport),
        QUERY_CAMPAIGN_FINDINGS_REQUEST_KIND => {
            Some(CampaignServiceOperation::QueryCampaignFindings)
        }
        QUERY_CAMPAIGN_FINDING_OCCURRENCES_REQUEST_KIND => {
            Some(CampaignServiceOperation::QueryCampaignFindingOccurrences)
        }
        GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignFindingOccurrenceObject)
        }
        GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignFindingTriageReplaySegment)
        }
        GET_CAMPAIGN_FINDING_OBJECT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignFindingObject)
        }
        EXPLAIN_CAMPAIGN_ATTEMPT_REQUEST_KIND => {
            Some(CampaignServiceOperation::ExplainCampaignAttempt)
        }
        GET_CAMPAIGN_PLANNER_RANKINGS_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignPlannerRankings)
        }
        GET_CAMPAIGN_FRONTIER_OBJECT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignFrontierObject)
        }
        GET_CAMPAIGN_CHOICE_OBJECT_REQUEST_KIND => {
            Some(CampaignServiceOperation::GetCampaignChoiceObject)
        }
        APPLY_COMMAND_REQUEST_KIND => Some(CampaignServiceOperation::ApplyCampaignCommand),
        PIN_CAMPAIGN_REQUEST_KIND => Some(CampaignServiceOperation::PinCampaign),
        SUBMIT_DISCOVERY_REQUEST_KIND => Some(CampaignServiceOperation::SubmitDiscoveryRequest),
        SUBMIT_BRANCH_REQUEST_KIND => Some(CampaignServiceOperation::SubmitBranchRequest),
        ATTACH_CAMPAIGN_RUNTIME_REQUEST_KIND => {
            Some(CampaignServiceOperation::AttachCampaignRuntime)
        }
        OPEN_CAMPAIGN_DEBUG_SESSION_REQUEST_KIND => Some(CampaignServiceOperation::DebugCampaign),
        _ => None,
    }
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

#[cfg(test)]
mod tests;
