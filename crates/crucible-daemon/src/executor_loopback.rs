//! Versioned Unix-stream loopback transport for executor component messages.
//!
//! The framing protocol contains no Rust-native layout or process-private
//! objects:
//!
//! ```text
//! ExecutorLoopbackFrameV5 = magic[8] | kind:u8 | reserved[3] |
//!                           body_length:u32be | canonical_body[body_length]
//! kind = 1 (SubmitAttemptRequest) | 2 (SubmitAttemptResponse) |
//!        3 (DescribeExecutorRequest) | 4 (ExecutorDescription) |
//!        5 (WatchExecutorCapacityRequest) | 6 (ExecutorCapacityReport) |
//!        7 (GetAttemptExecutionRequest) | 8 (GetAttemptExecutionResponse) |
//!        9 (CancelAttemptExecutionRequest) |
//!       10 (CancelAttemptExecutionResponse) |
//!       11 (CheckpointAttemptExecutionRequest) |
//!       12 (CheckpointAttemptExecutionResponse) |
//!       13 (ResumeAttemptExecutionRequest) |
//!       14 (ResumeAttemptExecutionResponse)
//! ```
//!
//! Each nested canonical message family carries and validates its own schema
//! version independently from the framing version.
//!
//! Both sides enforce the same 4-KiB component-message bound before allocation.
//! The coordinator still wraps [`LoopbackExecutorService`] in the shared
//! checked client, while the adapter itself also strictly authenticates the
//! response against the exact request.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crucible_campaign::{
    CampaignCodecError, CampaignHash, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, DaemonEpoch, DescribeExecutorRequest,
    ExecutorCapabilityService, ExecutorCapacityReport, ExecutorControlService, ExecutorDescription,
    ExecutorResumeService, ExecutorService, ExecutorStatusService, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptRequest,
    SubmitAttemptResponse, WatchExecutorCapacityRequest,
};

use crate::campaign_endpoint::{ExecutorLoopbackEndpointConfig, ExecutorLoopbackEndpointError};

const FRAME_MAGIC: &[u8; 8] = b"CRUCEX05";
const FRAME_HEADER_BYTES: usize = 16;
const SUBMIT_ATTEMPT_REQUEST_KIND: u8 = 1;
const SUBMIT_ATTEMPT_RESPONSE_KIND: u8 = 2;
const DESCRIBE_EXECUTOR_REQUEST_KIND: u8 = 3;
const EXECUTOR_DESCRIPTION_KIND: u8 = 4;
const WATCH_CAPACITY_REQUEST_KIND: u8 = 5;
const EXECUTOR_CAPACITY_REPORT_KIND: u8 = 6;
const GET_ATTEMPT_EXECUTION_REQUEST_KIND: u8 = 7;
const GET_ATTEMPT_EXECUTION_RESPONSE_KIND: u8 = 8;
const CANCEL_ATTEMPT_EXECUTION_REQUEST_KIND: u8 = 9;
const CANCEL_ATTEMPT_EXECUTION_RESPONSE_KIND: u8 = 10;
const CHECKPOINT_ATTEMPT_EXECUTION_REQUEST_KIND: u8 = 11;
const CHECKPOINT_ATTEMPT_EXECUTION_RESPONSE_KIND: u8 = 12;
const RESUME_ATTEMPT_EXECUTION_REQUEST_KIND: u8 = 13;
const RESUME_ATTEMPT_EXECUTION_RESPONSE_KIND: u8 = 14;
const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Default fairness ceiling for one executor connection.
pub const DEFAULT_EXECUTOR_REQUESTS_PER_CONNECTION: usize = 4_096;
/// Maximum complete exchanges admitted on one executor connection.
pub const MAX_EXECUTOR_REQUESTS_PER_CONNECTION: usize = 65_536;

/// Finite read/write deadlines for one loopback executor exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackExecutorTimeouts {
    read: Duration,
    write: Duration,
}

impl LoopbackExecutorTimeouts {
    /// Builds nonzero finite socket deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`LoopbackExecutorProtocolError::InvalidTimeout`] when either
    /// duration is zero or exceeds one hour.
    pub fn new(read: Duration, write: Duration) -> Result<Self, LoopbackExecutorProtocolError> {
        if read.is_zero()
            || write.is_zero()
            || read > MAX_LOOPBACK_TIMEOUT
            || write > MAX_LOOPBACK_TIMEOUT
        {
            return Err(LoopbackExecutorProtocolError::InvalidTimeout);
        }
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

impl Default for LoopbackExecutorTimeouts {
    fn default() -> Self {
        Self {
            read: DEFAULT_LOOPBACK_TIMEOUT,
            write: DEFAULT_LOOPBACK_TIMEOUT,
        }
    }
}

/// Coordinator-side executor service over a stream or retained endpoint.
pub struct LoopbackExecutorService {
    stream: UnixStream,
    timeouts: LoopbackExecutorTimeouts,
    reconnect_endpoint: Option<ExecutorLoopbackEndpointConfig>,
    expected_incarnation: Option<ExecutorIncarnation>,
}

#[derive(Clone, Copy)]
struct ExecutorIncarnation {
    daemon_epoch: DaemonEpoch,
    capability_digest: CampaignHash,
}

impl LoopbackExecutorService {
    /// Wraps a connected local Unix stream with default finite deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket deadlines cannot be configured.
    pub fn new(stream: UnixStream) -> Result<Self, LoopbackExecutorProtocolError> {
        Self::with_timeouts(stream, LoopbackExecutorTimeouts::default())
    }

    /// Wraps a connected stream with explicit nonzero finite deadlines.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket deadlines cannot be configured.
    pub fn with_timeouts(
        stream: UnixStream,
        timeouts: LoopbackExecutorTimeouts,
    ) -> Result<Self, LoopbackExecutorProtocolError> {
        configure_stream(&stream, timeouts)?;
        Ok(Self {
            stream,
            timeouts,
            reconnect_endpoint: None,
            expected_incarnation: None,
        })
    }

    /// Connects through one authenticated endpoint with default deadlines.
    ///
    /// The endpoint capability is retained for one bounded reconnect after a
    /// transport turnover. Callers must obtain and latch the initial executor
    /// description before dispatching any request other than description.
    ///
    /// # Errors
    ///
    /// Returns an endpoint or socket-configuration error when the initial
    /// authenticated connection cannot be established.
    pub fn connect(
        endpoint: ExecutorLoopbackEndpointConfig,
    ) -> Result<Self, LoopbackExecutorProtocolError> {
        Self::connect_with_timeouts(endpoint, LoopbackExecutorTimeouts::default())
    }

    /// Connects through one authenticated endpoint with explicit deadlines.
    ///
    /// # Errors
    ///
    /// Returns an endpoint or socket-configuration error when the initial
    /// authenticated connection cannot be established.
    pub fn connect_with_timeouts(
        endpoint: ExecutorLoopbackEndpointConfig,
        timeouts: LoopbackExecutorTimeouts,
    ) -> Result<Self, LoopbackExecutorProtocolError> {
        let stream = endpoint.connect()?;
        configure_stream(&stream, timeouts)?;
        Ok(Self {
            stream,
            timeouts,
            reconnect_endpoint: Some(endpoint),
            expected_incarnation: None,
        })
    }

    /// Returns the owned stream after the executor client shuts down.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    fn require_initial_description(&self) -> Result<(), LoopbackExecutorProtocolError> {
        if self.reconnect_endpoint.is_some() && self.expected_incarnation.is_none() {
            return Err(LoopbackExecutorProtocolError::InitialDescriptionRequired);
        }
        Ok(())
    }

    fn latch_description(
        &mut self,
        description: &ExecutorDescription,
    ) -> Result<(), LoopbackExecutorProtocolError> {
        let observed = ExecutorIncarnation {
            daemon_epoch: description.daemon_epoch(),
            capability_digest: description.capabilities().digest(),
        };
        let Some(expected) = self.expected_incarnation else {
            self.expected_incarnation = Some(observed);
            return Ok(());
        };
        if observed.daemon_epoch != expected.daemon_epoch {
            return Err(LoopbackExecutorProtocolError::ExecutorIncarnationChanged {
                expected: expected.daemon_epoch,
                observed: observed.daemon_epoch,
            });
        }
        if observed.capability_digest != expected.capability_digest {
            return Err(LoopbackExecutorProtocolError::ExecutorCapabilitiesChanged {
                expected: expected.capability_digest,
                observed: observed.capability_digest,
            });
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        request_kind: u8,
        response_kind: u8,
        request: &[u8],
    ) -> Result<Vec<u8>, LoopbackExecutorProtocolError> {
        match exchange_once(
            &mut self.stream,
            self.timeouts,
            request_kind,
            response_kind,
            request,
        ) {
            Ok(response) => Ok(response),
            Err(error) if error.is_transport_turnover() && self.reconnect_endpoint.is_some() => {
                let _ = self.stream.shutdown(Shutdown::Both);
                self.reconnect_and_revalidate()?;
                let result = exchange_once(
                    &mut self.stream,
                    self.timeouts,
                    request_kind,
                    response_kind,
                    request,
                );
                if result.is_err() {
                    let _ = self.stream.shutdown(Shutdown::Both);
                }
                result
            }
            Err(error) => {
                let _ = self.stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }

    fn reconnect_and_revalidate(&mut self) -> Result<(), LoopbackExecutorProtocolError> {
        let endpoint = self
            .reconnect_endpoint
            .as_ref()
            .ok_or(LoopbackExecutorProtocolError::ReconnectUnavailable)?;
        let mut stream = endpoint.connect()?;
        configure_stream(&stream, self.timeouts)?;

        let request = DescribeExecutorRequest::new().canonical_bytes();
        let response = exchange_once(
            &mut stream,
            self.timeouts,
            DESCRIBE_EXECUTOR_REQUEST_KIND,
            EXECUTOR_DESCRIPTION_KIND,
            &request,
        )?;
        let description = ExecutorDescription::from_canonical_bytes(&response)?;
        self.latch_description(&description)?;
        self.stream = stream;
        Ok(())
    }
}

impl ExecutorService for LoopbackExecutorService {
    type Error = LoopbackExecutorProtocolError;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                SUBMIT_ATTEMPT_REQUEST_KIND,
                SUBMIT_ATTEMPT_RESPONSE_KIND,
                &request_bytes,
            )?;
            SubmitAttemptResponse::from_canonical_bytes_for(request, &response).map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl ExecutorCapabilityService for LoopbackExecutorService {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        let request = DescribeExecutorRequest::new().canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                DESCRIBE_EXECUTOR_REQUEST_KIND,
                EXECUTOR_DESCRIPTION_KIND,
                &request,
            )?;
            let description = ExecutorDescription::from_canonical_bytes(&response)?;
            self.latch_description(&description)?;
            Ok(description)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                WATCH_CAPACITY_REQUEST_KIND,
                EXECUTOR_CAPACITY_REPORT_KIND,
                &request_bytes,
            )?;
            ExecutorCapacityReport::from_canonical_bytes(&response).map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl ExecutorStatusService for LoopbackExecutorService {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                GET_ATTEMPT_EXECUTION_REQUEST_KIND,
                GET_ATTEMPT_EXECUTION_RESPONSE_KIND,
                &request_bytes,
            )?;
            GetAttemptExecutionResponse::from_canonical_bytes_for(request, &response)
                .map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl ExecutorControlService for LoopbackExecutorService {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                CHECKPOINT_ATTEMPT_EXECUTION_REQUEST_KIND,
                CHECKPOINT_ATTEMPT_EXECUTION_RESPONSE_KIND,
                &request_bytes,
            )?;
            CheckpointAttemptExecutionResponse::from_canonical_bytes_for(request, &response)
                .map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                CANCEL_ATTEMPT_EXECUTION_REQUEST_KIND,
                CANCEL_ATTEMPT_EXECUTION_RESPONSE_KIND,
                &request_bytes,
            )?;
            CancelAttemptExecutionResponse::from_canonical_bytes_for(request, &response)
                .map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

impl ExecutorResumeService for LoopbackExecutorService {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.require_initial_description()?;
        let request_bytes = request.canonical_bytes();
        let result = (|| {
            let response = self.exchange(
                RESUME_ATTEMPT_EXECUTION_REQUEST_KIND,
                RESUME_ATTEMPT_EXECUTION_RESPONSE_KIND,
                &request_bytes,
            )?;
            ResumeAttemptExecutionResponse::from_canonical_bytes_for(request, &response)
                .map_err(Into::into)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
}

/// Serves one strict executor request/response exchange on a Unix stream.
///
/// A long-lived daemon calls this once per request on the same connection, or
/// closes the connection after any error. Service failures are not converted
/// into a misleading protocol rejection.
///
/// # Errors
///
/// Returns [`LoopbackExecutorServerError::Protocol`] for malformed framing,
/// canonical bytes, cross-request responses, or socket I/O. Returns
/// [`LoopbackExecutorServerError::Service`] when the executor cannot produce a
/// protocol response.
pub fn serve_loopback_executor_once<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    serve_loopback_executor_once_with_timeouts(stream, service, LoopbackExecutorTimeouts::default())
}

/// Serves one exchange with explicit finite read/write deadlines.
///
/// The stream is shut down in both directions before any error is returned, so
/// a peer never remains blocked waiting for a response the service abandoned.
///
/// # Errors
///
/// Returns the same failures as [`serve_loopback_executor_once`].
pub fn serve_loopback_executor_once_with_timeouts<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    let result = serve_loopback_executor_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn serve_loopback_executor_inner<S: ExecutorService>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>> {
    configure_stream(stream, timeouts)?;
    let request = read_frame(stream, SUBMIT_ATTEMPT_REQUEST_KIND, timeouts.read)?;
    let request = SubmitAttemptRequest::from_canonical_bytes(&request)?;
    let response = service
        .submit_attempt(&request)
        .map_err(LoopbackExecutorServerError::Service)?;
    response.validate_for(&request)?;
    write_frame(
        stream,
        SUBMIT_ATTEMPT_RESPONSE_KIND,
        &response.canonical_bytes(),
        timeouts.write,
    )?;
    Ok(())
}

/// Serves one submit, description, or capacity exchange on a Unix stream.
///
/// This is the general executor component dispatcher used after capability
/// negotiation is enabled. The submit-only entry point remains available for
/// narrow conformance tests.
///
/// # Errors
///
/// Returns [`LoopbackExecutorServerError::Protocol`] for an unknown operation,
/// malformed request, invalid service response, or bounded socket failure.
/// Returns [`LoopbackExecutorServerError::Service`] when the executor cannot
/// produce the selected protocol response. Every error shuts down the stream.
pub fn serve_loopback_executor_component_once<S>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>>
where
    S: ExecutorCapabilityService + ExecutorControlService + ExecutorResumeService,
{
    let result = serve_loopback_executor_component_inner(stream, service, timeouts);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

/// Serves one executor connection until clean peer shutdown or its fairness limit.
///
/// The service value remains connection-local while its cloneable underlying
/// executor actor may be shared by a bounded listener. Reaching the request
/// ceiling closes the connection after the last complete response so the peer
/// must re-enter listener admission. A clean close between frames is success;
/// a partial frame remains a protocol error.
///
/// # Errors
///
/// Returns [`LoopbackExecutorServerError::Protocol`] for an invalid request
/// limit, malformed framing, canonical bytes, invalid service response, or
/// bounded socket failure. Returns [`LoopbackExecutorServerError::Service`]
/// when the executor cannot produce a selected response. Every error shuts
/// down the stream.
pub fn serve_loopback_executor_component_connection_with_limits<S>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
    maximum_requests: usize,
) -> Result<(), LoopbackExecutorServerError<S::Error>>
where
    S: ExecutorCapabilityService + ExecutorControlService + ExecutorResumeService,
{
    if maximum_requests == 0 || maximum_requests > MAX_EXECUTOR_REQUESTS_PER_CONNECTION {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(LoopbackExecutorProtocolError::InvalidRequestLimit.into());
    }

    for _ in 0..maximum_requests {
        match serve_loopback_executor_component_inner(stream, service, timeouts) {
            Ok(()) => {}
            Err(LoopbackExecutorServerError::Protocol(
                LoopbackExecutorProtocolError::ConnectionClosed,
            )) => return Ok(()),
            Err(error) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(error);
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn serve_loopback_executor_component_inner<S>(
    stream: &mut UnixStream,
    service: &mut S,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorServerError<S::Error>>
where
    S: ExecutorCapabilityService + ExecutorControlService + ExecutorResumeService,
{
    configure_stream(stream, timeouts)?;
    let (kind, body) = read_frame_any(stream, timeouts.read)?;
    let (response_kind, response) = match kind {
        SUBMIT_ATTEMPT_REQUEST_KIND => {
            let request = SubmitAttemptRequest::from_canonical_bytes(&body)?;
            let response = service
                .submit_attempt(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&request)?;
            (SUBMIT_ATTEMPT_RESPONSE_KIND, response.canonical_bytes())
        }
        DESCRIBE_EXECUTOR_REQUEST_KIND => {
            DescribeExecutorRequest::from_canonical_bytes(&body)?;
            let response = service
                .describe_executor()
                .map_err(LoopbackExecutorServerError::Service)?;
            (EXECUTOR_DESCRIPTION_KIND, response.canonical_bytes())
        }
        WATCH_CAPACITY_REQUEST_KIND => {
            let request = WatchExecutorCapacityRequest::from_canonical_bytes(&body)?;
            let description = service
                .describe_executor()
                .map_err(LoopbackExecutorServerError::Service)?;
            validate_capacity_request(&request, &description)?;
            let response = service
                .watch_capacity(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&description, request.after_sequence())?;
            (EXECUTOR_CAPACITY_REPORT_KIND, response.canonical_bytes())
        }
        GET_ATTEMPT_EXECUTION_REQUEST_KIND => {
            let request = GetAttemptExecutionRequest::from_canonical_bytes(&body)?;
            let response = service
                .get_attempt_execution(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&request)?;
            (
                GET_ATTEMPT_EXECUTION_RESPONSE_KIND,
                response.canonical_bytes(),
            )
        }
        CANCEL_ATTEMPT_EXECUTION_REQUEST_KIND => {
            let request = CancelAttemptExecutionRequest::from_canonical_bytes(&body)?;
            let response = service
                .cancel_attempt_execution(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&request)?;
            (
                CANCEL_ATTEMPT_EXECUTION_RESPONSE_KIND,
                response.canonical_bytes(),
            )
        }
        CHECKPOINT_ATTEMPT_EXECUTION_REQUEST_KIND => {
            let request = CheckpointAttemptExecutionRequest::from_canonical_bytes(&body)?;
            let response = service
                .checkpoint_attempt_execution(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&request)?;
            (
                CHECKPOINT_ATTEMPT_EXECUTION_RESPONSE_KIND,
                response.canonical_bytes(),
            )
        }
        RESUME_ATTEMPT_EXECUTION_REQUEST_KIND => {
            let request = ResumeAttemptExecutionRequest::from_canonical_bytes(&body)?;
            let response = service
                .resume_attempt_execution(&request)
                .map_err(LoopbackExecutorServerError::Service)?;
            response.validate_for(&request)?;
            (
                RESUME_ATTEMPT_EXECUTION_RESPONSE_KIND,
                response.canonical_bytes(),
            )
        }
        _ => {
            return Err(LoopbackExecutorProtocolError::InvalidFrame {
                reason: "unknown-executor-component-request-kind",
            }
            .into());
        }
    };
    write_frame(stream, response_kind, &response, timeouts.write)?;
    Ok(())
}

fn validate_capacity_request(
    request: &WatchExecutorCapacityRequest,
    description: &ExecutorDescription,
) -> Result<(), CampaignCodecError> {
    if request.daemon_epoch() != description.daemon_epoch() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "watch capacity request daemon epoch is stale",
        });
    }
    if request.capability_digest() != description.capabilities().digest() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "watch capacity request capability digest is stale",
        });
    }
    Ok(())
}

/// Malformed, oversized, or unavailable loopback executor transport data.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackExecutorProtocolError {
    /// The Unix stream could not complete a bounded frame operation.
    #[error("executor loopback I/O failed")]
    Io(#[from] std::io::Error),
    /// An authenticated executor endpoint could not be connected.
    #[error(transparent)]
    Endpoint(#[from] ExecutorLoopbackEndpointError),
    /// Canonical request or response bytes failed strict validation.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A caller attempted to disable a required finite deadline.
    #[error("executor loopback read/write timeout must be between 1ns and 1h")]
    InvalidTimeout,
    /// A reconnectable client attempted work before capability negotiation.
    #[error("executor loopback requires an initial description before dispatch")]
    InitialDescriptionRequired,
    /// A raw connected stream has no retained endpoint reconnect capability.
    #[error("executor loopback reconnect endpoint is unavailable")]
    ReconnectUnavailable,
    /// A reconnected endpoint belongs to another executor daemon incarnation.
    #[error("executor loopback daemon incarnation changed during reconnect")]
    ExecutorIncarnationChanged {
        /// Daemon epoch authenticated before dispatch began.
        expected: DaemonEpoch,
        /// Daemon epoch reported by the reconnected endpoint.
        observed: DaemonEpoch,
    },
    /// A reconnected endpoint advertises another immutable capability set.
    #[error("executor loopback capabilities changed during reconnect")]
    ExecutorCapabilitiesChanged {
        /// Capability digest authenticated before dispatch began.
        expected: CampaignHash,
        /// Capability digest reported by the reconnected endpoint.
        observed: CampaignHash,
    },
    /// The peer closed cleanly between complete request frames.
    #[error("executor loopback peer closed the connection")]
    ConnectionClosed,
    /// A connection fairness limit was zero or exceeded 65,536 requests.
    #[error("executor loopback request limit is outside 1..=65,536")]
    InvalidRequestLimit,
    /// The fixed frame header violated the versioned protocol.
    #[error("executor loopback frame is invalid: {reason}")]
    InvalidFrame {
        /// Stable framing failure category.
        reason: &'static str,
    },
}

impl LoopbackExecutorProtocolError {
    fn is_transport_turnover(&self) -> bool {
        matches!(self, Self::Io(_) | Self::ConnectionClosed)
    }
}

fn configure_stream(
    stream: &UnixStream,
    timeouts: LoopbackExecutorTimeouts,
) -> Result<(), LoopbackExecutorProtocolError> {
    if timeouts.read.is_zero()
        || timeouts.write.is_zero()
        || timeouts.read > MAX_LOOPBACK_TIMEOUT
        || timeouts.write > MAX_LOOPBACK_TIMEOUT
    {
        return Err(LoopbackExecutorProtocolError::InvalidTimeout);
    }
    stream.set_read_timeout(Some(timeouts.read))?;
    stream.set_write_timeout(Some(timeouts.write))?;
    Ok(())
}

fn exchange_once(
    stream: &mut UnixStream,
    timeouts: LoopbackExecutorTimeouts,
    request_kind: u8,
    response_kind: u8,
    request: &[u8],
) -> Result<Vec<u8>, LoopbackExecutorProtocolError> {
    write_frame(stream, request_kind, request, timeouts.write)?;
    read_frame(stream, response_kind, timeouts.read)
}

/// Failure while serving one loopback executor exchange.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackExecutorServerError<E> {
    /// Framing, canonical validation, or socket I/O failed.
    #[error(transparent)]
    Protocol(#[from] LoopbackExecutorProtocolError),
    /// The underlying executor failed to produce a protocol response.
    #[error("executor service failed")]
    Service(E),
}

impl<E> From<CampaignCodecError> for LoopbackExecutorServerError<E> {
    fn from(error: CampaignCodecError) -> Self {
        Self::Protocol(LoopbackExecutorProtocolError::Codec(error))
    }
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    body: &[u8],
    timeout: Duration,
) -> Result<(), LoopbackExecutorProtocolError> {
    if body.len() > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let length =
        u32::try_from(body.len()).map_err(|_| LoopbackExecutorProtocolError::InvalidFrame {
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

fn read_frame(
    stream: &mut UnixStream,
    expected_kind: u8,
    timeout: Duration,
) -> Result<Vec<u8>, LoopbackExecutorProtocolError> {
    let (kind, body) = match read_frame_any(stream, timeout) {
        Err(LoopbackExecutorProtocolError::ConnectionClosed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "executor loopback peer closed before a response",
            )
            .into());
        }
        result => result?,
    };
    if kind != expected_kind {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "unexpected-message-kind",
        });
    }
    Ok(body)
}

fn read_frame_any(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>), LoopbackExecutorProtocolError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let deadline = operation_deadline(timeout)?;
    read_exact_until(stream, &mut header, deadline, true)?;
    if &header[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "unsupported-frame-version",
        });
    }
    if header[9..12] != [0; 3] {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "nonzero-reserved-bits",
        });
    }
    let length = u32::from_be_bytes(header[12..].try_into().map_err(|_| {
        LoopbackExecutorProtocolError::InvalidFrame {
            reason: "invalid-length-field",
        }
    })?) as usize;
    if length > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(LoopbackExecutorProtocolError::InvalidFrame {
            reason: "component-message-too-large",
        });
    }
    let mut body = vec![0; length];
    read_exact_until(stream, &mut body, deadline, false)?;
    Ok((header[8], body))
}

fn operation_deadline(timeout: Duration) -> Result<Instant, LoopbackExecutorProtocolError> {
    if timeout.is_zero() || timeout > MAX_LOOPBACK_TIMEOUT {
        return Err(LoopbackExecutorProtocolError::InvalidTimeout);
    }
    transport_now()
        .checked_add(timeout)
        .ok_or(LoopbackExecutorProtocolError::InvalidTimeout)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
    clean_initial_eof: bool,
) -> Result<(), LoopbackExecutorProtocolError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(transport_now())
            .ok_or_else(timeout_io_error)?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) if offset == 0 && clean_initial_eof => {
                return Err(LoopbackExecutorProtocolError::ConnectionClosed);
            }
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "executor loopback peer closed a partial frame",
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
) -> Result<(), LoopbackExecutorProtocolError> {
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

fn timeout_io_error() -> LoopbackExecutorProtocolError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "executor loopback absolute operation deadline elapsed",
    )
    .into()
}

// Wall-independent monotonic time bounds only operational socket blocking; it
// never enters a campaign object, semantic result, or deterministic decision.
// crucible-lint: allow clippy-disallowed-method -- the bounded host operation is operational only and cannot enter modeled state.
#[allow(clippy::disallowed_methods)]
fn transport_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
