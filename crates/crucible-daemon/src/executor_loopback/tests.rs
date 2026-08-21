//! Conformance tests for the strict executor Unix-stream adapter.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::Write;
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId,
    CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, DaemonEpoch,
    ExecutionId, ExecutionRetentionIntent, ExecutorCapabilitySet, ExecutorClient,
    ExecutorCompatibilityProfile, ExecutorControlService, ExecutorDescription,
    ExecutorMaterializationCapability, ExecutorRejection, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    SubmitAttemptDisposition,
};

use super::*;

struct RejectingExecutor;

impl ExecutorService for RejectingExecutor {
    type Error = Infallible;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        Ok(SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Backpressure,
            },
        )
        .expect("bounded response"))
    }
}

struct CapabilityExecutor {
    description: ExecutorDescription,
    report: ExecutorCapacityReport,
}

impl ExecutorService for CapabilityExecutor {
    type Error = Infallible;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        RejectingExecutor.submit_attempt(request)
    }
}

impl ExecutorCapabilityService for CapabilityExecutor {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        Ok(self.description.clone())
    }

    fn watch_capacity(
        &mut self,
        _request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        Ok(self.report.clone())
    }
}

impl ExecutorStatusService for CapabilityExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        Ok(
            GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::Running)
                .expect("bounded status response"),
        )
    }
}

impl ExecutorControlService for CapabilityExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        Ok(CheckpointAttemptExecutionResponse::new(
            request,
            CheckpointAttemptExecutionDisposition::AlreadyRequested,
        )
        .expect("bounded checkpoint response"))
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        Ok(CancelAttemptExecutionResponse::new(
            request,
            CancelAttemptExecutionDisposition::AlreadyCanceled,
        )
        .expect("bounded cancellation response"))
    }
}

#[derive(Debug)]
struct InjectedServiceFailure;

struct FailingExecutor;

impl ExecutorService for FailingExecutor {
    type Error = InjectedServiceFailure;

    fn submit_attempt(
        &mut self,
        _request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        Err(InjectedServiceFailure)
    }
}

#[test]
fn direct_and_loopback_services_return_identical_checked_responses() {
    let request = request(0x11);
    let direct = ExecutorClient::new(RejectingExecutor)
        .submit_attempt(&request)
        .expect("direct checked response");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        serve_loopback_executor_once(&mut server_stream, &mut RejectingExecutor)
            .expect("serve request");
    });
    let loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    )
    .submit_attempt(&request)
    .expect("loopback checked response");
    server.join().expect("server thread");

    assert_eq!(loopback, direct);
}

#[test]
fn direct_and_loopback_capability_negotiation_are_identical() {
    let (description, report) = capability_fixture();
    let mut direct = ExecutorClient::new(CapabilityExecutor {
        description: description.clone(),
        report: report.clone(),
    });
    let direct_description = direct.describe_executor().expect("direct description");
    let direct_report = direct
        .watch_capacity(&direct_description, Some(10))
        .expect("direct capacity");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server_description = description.clone();
    let server_report = report.clone();
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description: server_description,
            report: server_report,
        };
        serve_loopback_executor_component_once(
            &mut server_stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve description");
        serve_loopback_executor_component_once(
            &mut server_stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve capacity");
    });
    let mut loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    );
    let loopback_description = loopback.describe_executor().expect("loopback description");
    let loopback_report = loopback
        .watch_capacity(&loopback_description, Some(10))
        .expect("loopback capacity");
    server.join().expect("server thread");

    assert_eq!(loopback_description, direct_description);
    assert_eq!(loopback_report, direct_report);
}

#[test]
fn direct_and_loopback_execution_status_are_identical() {
    let (description, report) = capability_fixture();
    let assignment = request(0x19);
    let status_request = GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x61; 16]).expect("execution"),
    )
    .expect("status request");
    let direct = ExecutorClient::new(CapabilityExecutor {
        description: description.clone(),
        report: report.clone(),
    })
    .get_attempt_execution(&status_request)
    .expect("direct status");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description,
            report,
        };
        serve_loopback_executor_component_once(
            &mut server_stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve status");
    });
    let loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    )
    .get_attempt_execution(&status_request)
    .expect("loopback status");
    server.join().expect("server thread");

    assert_eq!(loopback, direct);
}

#[test]
fn direct_and_loopback_execution_cancellation_are_identical() {
    let (description, report) = capability_fixture();
    let assignment = request(0x1a);
    let cancel_request = CancelAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x62; 16]).expect("execution"),
    )
    .expect("cancellation request");
    let direct = ExecutorClient::new(CapabilityExecutor {
        description: description.clone(),
        report: report.clone(),
    })
    .cancel_attempt_execution(&cancel_request)
    .expect("direct cancellation");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description,
            report,
        };
        serve_loopback_executor_component_once(
            &mut server_stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve cancellation");
    });
    let loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    )
    .cancel_attempt_execution(&cancel_request)
    .expect("loopback cancellation");
    server.join().expect("server thread");

    assert_eq!(loopback, direct);
}

#[test]
fn direct_and_loopback_checkpoint_requests_are_identical() {
    let (description, report) = capability_fixture();
    let assignment = request(0x1b);
    let checkpoint_request = CheckpointAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x63; 16]).expect("execution"),
    )
    .expect("checkpoint request");
    let direct = ExecutorClient::new(CapabilityExecutor {
        description: description.clone(),
        report: report.clone(),
    })
    .checkpoint_attempt_execution(&checkpoint_request)
    .expect("direct checkpoint request");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description,
            report,
        };
        serve_loopback_executor_component_once(
            &mut server_stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve checkpoint request");
    });
    let loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    )
    .checkpoint_attempt_execution(&checkpoint_request)
    .expect("loopback checkpoint request");
    server.join().expect("server thread");

    assert_eq!(loopback, direct);
}

#[test]
fn frame_header_and_canonical_body_have_one_exact_encoding() {
    let request = request(0x12);
    let body = request.canonical_bytes();
    let (mut writer, mut reader) = UnixStream::pair().expect("loopback pair");
    write_frame(
        &mut writer,
        SUBMIT_ATTEMPT_REQUEST_KIND,
        &body,
        DEFAULT_LOOPBACK_TIMEOUT,
    )
    .expect("write frame");

    let mut encoded = vec![0; FRAME_HEADER_BYTES + body.len()];
    reader.read_exact(&mut encoded).expect("read exact frame");
    assert_eq!(&encoded[..8], b"CRUCEX04");
    assert_eq!(encoded[8], SUBMIT_ATTEMPT_REQUEST_KIND);
    assert_eq!(&encoded[9..12], &[0, 0, 0]);
    assert_eq!(
        &encoded[12..16],
        &u32::try_from(body.len())
            .expect("bounded body")
            .to_be_bytes()
    );
    assert_eq!(&encoded[16..], body);
}

#[test]
fn frame_bounds_and_reserved_bytes_fail_before_service_invocation() {
    let (mut client, mut server) = UnixStream::pair().expect("loopback pair");
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
    header[8] = SUBMIT_ATTEMPT_REQUEST_KIND;
    header[9] = 1;
    client.write_all(&header).expect("write malformed header");
    assert!(matches!(
        serve_loopback_executor_once(&mut server, &mut RejectingExecutor),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::InvalidFrame {
                reason: "nonzero-reserved-bits"
            }
        ))
    ));

    let (mut client, mut server) = UnixStream::pair().expect("oversized pair");
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
    header[8] = SUBMIT_ATTEMPT_REQUEST_KIND;
    let oversized =
        u32::try_from(MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES + 1).expect("bounded test length");
    header[12..].copy_from_slice(&oversized.to_be_bytes());
    client.write_all(&header).expect("write oversized header");
    assert!(matches!(
        serve_loopback_executor_once(&mut server, &mut RejectingExecutor),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::InvalidFrame {
                reason: "component-message-too-large"
            }
        ))
    ));
}

#[test]
fn client_rejects_a_canonical_response_for_another_request() {
    let submitted = request(0x21);
    let other = request(0x22);
    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let _request = read_frame(
            &mut server_stream,
            SUBMIT_ATTEMPT_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read request frame");
        let response = SubmitAttemptResponse::new(
            &other,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Backpressure,
            },
        )
        .expect("other response");
        write_frame(
            &mut server_stream,
            SUBMIT_ATTEMPT_RESPONSE_KIND,
            &response.canonical_bytes(),
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write wrong response");
        thread::sleep(Duration::from_millis(100));
    });
    let deadlines =
        LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
            .expect("finite deadlines");
    let mut service = LoopbackExecutorService::with_timeouts(client_stream, deadlines)
        .expect("configure client deadlines");
    let error = service
        .submit_attempt(&submitted)
        .expect_err("cross-request response must fail");
    assert!(matches!(error, LoopbackExecutorProtocolError::Codec(_)));
    let poisoned = service
        .submit_attempt(&submitted)
        .expect_err("protocol failure must poison the connection");
    assert!(matches!(
        poisoned,
        LoopbackExecutorProtocolError::Io(ref error)
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    server.join().expect("server thread");
}

#[test]
fn client_poisons_after_cross_execution_status_response() {
    let assignment = request(0x25);
    let submitted = GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x71; 16]).expect("execution"),
    )
    .expect("status request");
    let other = GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x72; 16]).expect("other execution"),
    )
    .expect("other status request");
    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let _request = read_frame(
            &mut server_stream,
            GET_ATTEMPT_EXECUTION_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read status request");
        let response =
            GetAttemptExecutionResponse::new(&other, GetAttemptExecutionDisposition::NotCurrent)
                .expect("other response");
        write_frame(
            &mut server_stream,
            GET_ATTEMPT_EXECUTION_RESPONSE_KIND,
            &response.canonical_bytes(),
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write wrong status response");
        thread::sleep(Duration::from_millis(100));
    });
    let deadlines =
        LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
            .expect("finite deadlines");
    let mut service = LoopbackExecutorService::with_timeouts(client_stream, deadlines)
        .expect("configure client deadlines");
    assert!(matches!(
        service.get_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Codec(_))
    ));
    assert!(matches!(
        service.get_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Io(ref error))
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    server.join().expect("server thread");
}

#[test]
fn client_poisons_after_cross_execution_cancellation_response() {
    let assignment = request(0x26);
    let submitted = CancelAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x73; 16]).expect("execution"),
    )
    .expect("cancellation request");
    let other = CancelAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x74; 16]).expect("other execution"),
    )
    .expect("other cancellation request");
    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let _request = read_frame(
            &mut server_stream,
            CANCEL_ATTEMPT_EXECUTION_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read cancellation request");
        let response = CancelAttemptExecutionResponse::new(
            &other,
            CancelAttemptExecutionDisposition::NotCurrent,
        )
        .expect("other response");
        write_frame(
            &mut server_stream,
            CANCEL_ATTEMPT_EXECUTION_RESPONSE_KIND,
            &response.canonical_bytes(),
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write wrong cancellation response");
        thread::sleep(Duration::from_millis(100));
    });
    let deadlines =
        LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
            .expect("finite deadlines");
    let mut service = LoopbackExecutorService::with_timeouts(client_stream, deadlines)
        .expect("configure client deadlines");
    assert!(matches!(
        service.cancel_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Codec(_))
    ));
    assert!(matches!(
        service.cancel_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Io(ref error))
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    server.join().expect("server thread");
}

#[test]
fn client_poisons_after_cross_execution_checkpoint_response() {
    let assignment = request(0x27);
    let submitted = CheckpointAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x75; 16]).expect("execution"),
    )
    .expect("checkpoint request");
    let other = CheckpointAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x76; 16]).expect("other execution"),
    )
    .expect("other checkpoint request");
    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        let _request = read_frame(
            &mut server_stream,
            CHECKPOINT_ATTEMPT_EXECUTION_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read checkpoint request");
        let response = CheckpointAttemptExecutionResponse::new(
            &other,
            CheckpointAttemptExecutionDisposition::NotCurrent,
        )
        .expect("other response");
        write_frame(
            &mut server_stream,
            CHECKPOINT_ATTEMPT_EXECUTION_RESPONSE_KIND,
            &response.canonical_bytes(),
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write wrong checkpoint response");
        thread::sleep(Duration::from_millis(100));
    });
    let deadlines =
        LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
            .expect("finite deadlines");
    let mut service = LoopbackExecutorService::with_timeouts(client_stream, deadlines)
        .expect("configure client deadlines");
    assert!(matches!(
        service.checkpoint_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Codec(_))
    ));
    assert!(matches!(
        service.checkpoint_attempt_execution(&submitted),
        Err(LoopbackExecutorProtocolError::Io(ref error))
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    ));
    server.join().expect("server thread");
}

#[test]
fn executor_loopback_v4_rejects_v3_frames() {
    let (mut client, mut server) = UnixStream::pair().expect("loopback pair");
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..8].copy_from_slice(b"CRUCEX03");
    header[8] = SUBMIT_ATTEMPT_REQUEST_KIND;
    client.write_all(&header).expect("write legacy header");

    assert!(matches!(
        serve_loopback_executor_once(&mut server, &mut RejectingExecutor),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::InvalidFrame {
                reason: "unsupported-frame-version"
            }
        ))
    ));
}

#[test]
fn partial_frames_and_nonreading_peers_hit_finite_deadlines() {
    let deadlines =
        LoopbackExecutorTimeouts::new(Duration::from_millis(20), Duration::from_millis(20))
            .expect("finite deadlines");

    let (mut client, mut server) = UnixStream::pair().expect("partial-header pair");
    client.write_all(b"C").expect("write partial header");
    assert!(matches!(
        serve_loopback_executor_once_with_timeouts(&mut server, &mut RejectingExecutor, deadlines,),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::Io(_)
        ))
    ));

    let (mut client, mut server) = UnixStream::pair().expect("partial-body pair");
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
    header[8] = SUBMIT_ATTEMPT_REQUEST_KIND;
    header[12..].copy_from_slice(&16_u32.to_be_bytes());
    client.write_all(&header).expect("write body header");
    client.write_all(b"x").expect("write partial body");
    assert!(matches!(
        serve_loopback_executor_once_with_timeouts(&mut server, &mut RejectingExecutor, deadlines,),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::Io(_)
        ))
    ));

    let (mut drip_client, mut drip_server) = UnixStream::pair().expect("drip pair");
    let drip = thread::spawn(move || {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
        header[8] = SUBMIT_ATTEMPT_REQUEST_KIND;
        for byte in header {
            if drip_client.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    assert!(matches!(
        serve_loopback_executor_once_with_timeouts(
            &mut drip_server,
            &mut RejectingExecutor,
            deadlines,
        ),
        Err(LoopbackExecutorServerError::Protocol(
            LoopbackExecutorProtocolError::Io(_)
        ))
    ));
    drip.join().expect("drip peer thread");

    let (mut writer, _nonreading_peer) = UnixStream::pair().expect("nonreading pair");
    configure_stream(&writer, deadlines).expect("configure write deadline");
    rustix::net::sockopt::set_socket_send_buffer_size(&writer, 1024).expect("shrink send buffer");
    let body = [0_u8; MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES];
    let mut timed_out = false;
    for _ in 0..1024 {
        if let Err(error) = write_frame(
            &mut writer,
            SUBMIT_ATTEMPT_RESPONSE_KIND,
            &body,
            deadlines.write(),
        ) {
            assert!(matches!(error, LoopbackExecutorProtocolError::Io(_)));
            timed_out = true;
            break;
        }
    }
    assert!(
        timed_out,
        "nonreading peer must not permit unbounded writes"
    );
}

#[test]
fn service_failure_closes_the_stream_and_unblocks_the_client() {
    let request = request(0x23);
    let (client_stream, mut server_stream) = UnixStream::pair().expect("loopback pair");
    let server = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_executor_once(&mut server_stream, &mut FailingExecutor),
            Err(LoopbackExecutorServerError::Service(InjectedServiceFailure))
        ));
    });
    let error = LoopbackExecutorService::new(client_stream)
        .expect("configure client deadlines")
        .submit_attempt(&request)
        .expect_err("service failure must unblock client");
    server.join().expect("server thread");
    assert!(matches!(error, LoopbackExecutorProtocolError::Io(_)));
}

fn request(assignment_byte: u8) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x31; 16]).expect("epoch"),
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            0x41,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            0x51,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("request")
}

fn capability_fixture() -> (ExecutorDescription, ExecutorCapacityReport) {
    let epoch = DaemonEpoch::from_bytes([0x71; 16]).expect("epoch");
    let compatibility = ExecutorCompatibilityProfile::new(
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("compatibility");
    let capabilities = ExecutorCapabilitySet::new(
        compatibility,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([
            ExecutorMaterializationCapability::ThinReplay,
            ExecutorMaterializationCapability::ExactRestore,
        ]),
        4,
        AttemptResourceLimits::new(4, 4096, 8192, 64).expect("resource ceiling"),
        BTreeSet::from([crucible_campaign::CampaignHash::derive(
            "crucible.test.executor-loopback-namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    let description = ExecutorDescription::new(epoch, capabilities).expect("description");
    let report = ExecutorCapacityReport::new(
        epoch,
        description.capabilities().digest(),
        11,
        2,
        2,
        2048,
        4096,
        BTreeSet::new(),
    )
    .expect("capacity");
    (description, report)
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
