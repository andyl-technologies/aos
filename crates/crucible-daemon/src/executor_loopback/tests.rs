//! Conformance tests for the strict executor Unix-stream adapter.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::{ErrorKind, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId,
    CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, DaemonEpoch,
    ExactCheckpointId, ExecutionId, ExecutionRetentionIntent, ExecutorCapabilitySet,
    ExecutorClient, ExecutorCompatibilityProfile, ExecutorControlService, ExecutorDescription,
    ExecutorMaterializationCapability, ExecutorRejection, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, SubmitAttemptDisposition,
};
use tempfile::TempDir;

use crate::{
    ExecutorCapacity, LocalExecutorCapabilityService, LocalExecutorSupervisor,
    MemoryAssignmentLedger,
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

impl ExecutorResumeService for CapabilityExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        Ok(ResumeAttemptExecutionResponse::new(
            request,
            ResumeAttemptExecutionDisposition::AlreadyCanceled,
        )
        .expect("bounded resume response"))
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
fn direct_and_loopback_resume_requests_are_identical() {
    let (description, report) = capability_fixture();
    let assignment = request(0x1c);
    let checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.2.{}",
        encode_hex(&[0x64; 32]),
    ))
    .expect("checkpoint");
    let resume_request = ResumeAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x64; 16]).expect("prior execution"),
        checkpoint,
    )
    .expect("resume request");
    let direct = ExecutorClient::new(CapabilityExecutor {
        description: description.clone(),
        report: report.clone(),
    })
    .resume_attempt_execution(&resume_request)
    .expect("direct resume request");

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
        .expect("serve resume request");
    });
    let loopback = ExecutorClient::new(
        LoopbackExecutorService::new(client_stream).expect("configure client deadlines"),
    )
    .resume_attempt_execution(&resume_request)
    .expect("loopback resume request");
    server.join().expect("server thread");

    assert_eq!(loopback, direct);
}

#[test]
fn reconnects_after_the_server_fairness_ceiling() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("fairness-reconnect");
    let (description, report) = capability_fixture();
    let server_description = description.clone();
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description: server_description,
            report,
        };
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept reconnecting client");
            serve_loopback_executor_component_connection_with_limits(
                &mut stream,
                &mut service,
                LoopbackExecutorTimeouts::default(),
                3,
            )
            .expect("serve fairness-bounded connection");
        }
    });

    let assignment = request(0x1d);
    let status_request = GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x75; 16]).expect("execution"),
    )
    .expect("status request");
    let checkpoint_request = CheckpointAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x75; 16]).expect("execution"),
    )
    .expect("checkpoint request");
    let mut client = ExecutorClient::new(
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint"),
    );
    let negotiated = client.describe_executor().expect("initial description");
    client
        .get_attempt_execution(&status_request)
        .expect("status before fairness close");
    client
        .checkpoint_attempt_execution(&checkpoint_request)
        .expect("checkpoint at fairness close");
    let submitted = client
        .submit_attempt(&assignment)
        .expect("submit after authenticated reconnect");
    drop(client);
    server.join().expect("join reconnecting executor server");

    assert_eq!(negotiated, description);
    assert!(matches!(
        submitted.disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Backpressure
        }
    ));
}

#[test]
fn reconnectable_client_requires_initial_description_before_dispatch() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("initial-description");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept initial connection");
        let deadlines =
            LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
                .expect("short close deadline");
        assert!(matches!(
            read_frame(&mut stream, SUBMIT_ATTEMPT_REQUEST_KIND, deadlines.read()),
            Err(LoopbackExecutorProtocolError::Io(_))
                | Err(LoopbackExecutorProtocolError::ConnectionClosed)
        ));
    });

    let mut service =
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint");
    assert!(matches!(
        service.submit_attempt(&request(0x20)),
        Err(LoopbackExecutorProtocolError::InitialDescriptionRequired)
    ));
    drop(service);
    server.join().expect("join initial-description server");
}

#[test]
fn one_request_ceiling_exhausts_the_single_retry() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("retry-exhaustion");
    let (description, report) = capability_fixture();
    let server_description = description.clone();
    let server = thread::spawn(move || {
        let mut service = CapabilityExecutor {
            description: server_description,
            report,
        };
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept bounded connection");
            serve_loopback_executor_component_connection_with_limits(
                &mut stream,
                &mut service,
                LoopbackExecutorTimeouts::default(),
                1,
            )
            .expect("serve one description");
        }
        assert_no_new_connection(&listener);
    });

    let mut service =
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint");
    assert_eq!(
        service.describe_executor().expect("initial description"),
        description
    );
    assert!(matches!(
        service.submit_attempt(&request(0x21)),
        Err(LoopbackExecutorProtocolError::Io(_))
            | Err(LoopbackExecutorProtocolError::ConnectionClosed)
    ));
    drop(service);
    server.join().expect("join retry-exhaustion server");
}

#[test]
fn response_loss_replays_exact_bytes_without_duplicate_admission() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("response-loss");
    let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("daemon epoch");
    let (basis, _) = capability_fixture();
    let description =
        ExecutorDescription::new(epoch, basis.capabilities().clone()).expect("description");
    let validations = Arc::new(AtomicUsize::new(0));
    let validation_counter = Arc::clone(&validations);
    let validator = move |_request: &SubmitAttemptRequest| {
        validation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    };
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        validator,
        epoch,
        ExecutorCapacity::new(4, 4, 4096, 8192, 64).expect("executor capacity"),
    );
    let mut local = LocalExecutorCapabilityService::new(supervisor, description.clone())
        .expect("capability service");
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().expect("accept initial connection");
        serve_loopback_executor_component_once(
            &mut first,
            &mut local,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve initial description");
        let first_request = read_frame(
            &mut first,
            SUBMIT_ATTEMPT_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read first submit");
        let first_typed = SubmitAttemptRequest::from_canonical_bytes(&first_request)
            .expect("decode first submit");
        let first_response = local
            .submit_attempt(&first_typed)
            .expect("admit first submit");
        first.shutdown(Shutdown::Both).expect("drop first response");

        let (mut second, _) = listener.accept().expect("accept retry connection");
        serve_loopback_executor_component_once(
            &mut second,
            &mut local,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve reconnect description");
        let second_request = read_frame(
            &mut second,
            SUBMIT_ATTEMPT_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read retried submit");
        let second_typed = SubmitAttemptRequest::from_canonical_bytes(&second_request)
            .expect("decode retried submit");
        let second_response = local
            .submit_attempt(&second_typed)
            .expect("replay admitted submit");
        write_frame(
            &mut second,
            SUBMIT_ATTEMPT_RESPONSE_KIND,
            &second_response.canonical_bytes(),
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write replay response");
        (
            first_request,
            second_request,
            first_response,
            second_response,
        )
    });

    let request = request(0x1e);
    let mut client = ExecutorClient::new(
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint"),
    );
    assert_eq!(
        client.describe_executor().expect("initial description"),
        description
    );
    let response = client
        .submit_attempt(&request)
        .expect("recover response-lost submit");
    drop(client);
    let (first_bytes, second_bytes, first_response, second_response) =
        server.join().expect("join response-loss server");

    assert_eq!(first_bytes, request.canonical_bytes());
    assert_eq!(second_bytes, first_bytes);
    assert_eq!(second_response, first_response);
    assert_eq!(response, first_response);
    assert_eq!(validations.load(Ordering::Relaxed), 1);
}

#[test]
fn reconnect_refuses_a_changed_daemon_epoch_before_resend() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("changed-epoch");
    let (initial, initial_report) = capability_fixture();
    let changed_epoch = DaemonEpoch::from_bytes([0x72; 16]).expect("changed epoch");
    let changed = ExecutorDescription::new(changed_epoch, initial.capabilities().clone())
        .expect("changed description");
    let changed_report = ExecutorCapacityReport::new(
        changed_epoch,
        changed.capabilities().digest(),
        11,
        2,
        2,
        2048,
        4096,
        BTreeSet::new(),
    )
    .expect("changed capacity");
    let server_initial = initial.clone();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().expect("accept initial connection");
        let mut initial_service = CapabilityExecutor {
            description: server_initial,
            report: initial_report,
        };
        serve_loopback_executor_component_once(
            &mut first,
            &mut initial_service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve initial description");
        first
            .shutdown(Shutdown::Both)
            .expect("close old incarnation");

        let (mut second, _) = listener.accept().expect("accept reconnect");
        let mut changed_service = CapabilityExecutor {
            description: changed,
            report: changed_report,
        };
        serve_loopback_executor_component_once(
            &mut second,
            &mut changed_service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve changed description");
        let deadlines =
            LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
                .expect("short close deadline");
        assert!(matches!(
            read_frame(&mut second, SUBMIT_ATTEMPT_REQUEST_KIND, deadlines.read()),
            Err(LoopbackExecutorProtocolError::Io(_))
                | Err(LoopbackExecutorProtocolError::ConnectionClosed)
        ));
    });

    let mut service =
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint");
    assert_eq!(
        service.describe_executor().expect("initial description"),
        initial
    );
    let error = service
        .submit_attempt(&request(0x1f))
        .expect_err("changed daemon epoch must refuse resend");
    assert!(matches!(
        error,
        LoopbackExecutorProtocolError::ExecutorIncarnationChanged {
            expected,
            observed,
        } if expected == initial.daemon_epoch() && observed == changed_epoch
    ));
    server.join().expect("join changed-incarnation server");
}

#[test]
fn reconnect_refuses_changed_capabilities_before_resend() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("changed-capabilities");
    let (initial, initial_report) = capability_fixture();
    let initial_capabilities = initial.capabilities();
    let changed_capabilities = ExecutorCapabilitySet::new(
        initial_capabilities.compatibility().clone(),
        initial_capabilities.host_architecture(),
        BTreeSet::from([
            String::from("deterministic-tcg-v1"),
            String::from("deterministic-tcg-v2"),
        ]),
        initial_capabilities.materialization().clone(),
        initial_capabilities.maximum_slots(),
        initial_capabilities.resource_ceiling(),
        initial_capabilities.store_namespaces().clone(),
    )
    .expect("changed capabilities");
    let changed = ExecutorDescription::new(initial.daemon_epoch(), changed_capabilities)
        .expect("changed description");
    let changed_digest = changed.capabilities().digest();
    let changed_report = ExecutorCapacityReport::new(
        changed.daemon_epoch(),
        changed_digest,
        11,
        2,
        2,
        2048,
        4096,
        BTreeSet::new(),
    )
    .expect("changed capacity");
    let server_initial = initial.clone();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().expect("accept initial connection");
        let mut initial_service = CapabilityExecutor {
            description: server_initial,
            report: initial_report,
        };
        serve_loopback_executor_component_once(
            &mut first,
            &mut initial_service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve initial description");
        first
            .shutdown(Shutdown::Both)
            .expect("close old capabilities");

        let (mut second, _) = listener.accept().expect("accept reconnect");
        let mut changed_service = CapabilityExecutor {
            description: changed,
            report: changed_report,
        };
        serve_loopback_executor_component_once(
            &mut second,
            &mut changed_service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve changed description");
        let deadlines =
            LoopbackExecutorTimeouts::new(Duration::from_millis(250), Duration::from_millis(250))
                .expect("short close deadline");
        assert!(matches!(
            read_frame(&mut second, SUBMIT_ATTEMPT_REQUEST_KIND, deadlines.read()),
            Err(LoopbackExecutorProtocolError::Io(_))
                | Err(LoopbackExecutorProtocolError::ConnectionClosed)
        ));
    });

    let mut service =
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint");
    assert_eq!(
        service.describe_executor().expect("initial description"),
        initial
    );
    let error = service
        .submit_attempt(&request(0x22))
        .expect_err("changed capabilities must refuse resend");
    assert!(matches!(
        error,
        LoopbackExecutorProtocolError::ExecutorCapabilitiesChanged {
            expected,
            observed,
        } if expected == initial.capabilities().digest() && observed == changed_digest
    ));
    server.join().expect("join changed-capabilities server");
}

#[test]
fn invalid_typed_response_does_not_reconnect() {
    let (_directory, endpoint, listener, _guard) = bound_executor_endpoint("invalid-response");
    let (description, report) = capability_fixture();
    let server_description = description.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept initial connection");
        let mut service = CapabilityExecutor {
            description: server_description,
            report,
        };
        serve_loopback_executor_component_once(
            &mut stream,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve initial description");
        read_frame(
            &mut stream,
            SUBMIT_ATTEMPT_REQUEST_KIND,
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("read submit request");
        write_frame(
            &mut stream,
            SUBMIT_ATTEMPT_RESPONSE_KIND,
            &[0],
            DEFAULT_LOOPBACK_TIMEOUT,
        )
        .expect("write invalid typed response");
        assert_no_new_connection(&listener);
    });

    let mut service =
        LoopbackExecutorService::connect(endpoint).expect("connect executor endpoint");
    assert_eq!(
        service.describe_executor().expect("initial description"),
        description
    );
    assert!(matches!(
        service.submit_attempt(&request(0x24)),
        Err(LoopbackExecutorProtocolError::Codec(_))
    ));
    drop(service);
    server.join().expect("join invalid-response server");
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
    assert_eq!(&encoded[..8], b"CRUCEX05");
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

fn bound_executor_endpoint(
    socket_name: &str,
) -> (
    TempDir,
    ExecutorLoopbackEndpointConfig,
    UnixListener,
    crate::campaign_endpoint::LocalEndpointGuard,
) {
    let directory = tempfile::tempdir().expect("executor endpoint directory");
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join(socket_name),
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        0o600,
    )
    .expect("executor endpoint config");
    let (listener, guard) = endpoint
        .bind()
        .expect("bind executor endpoint")
        .into_parts();
    (directory, endpoint, listener, guard)
}

fn assert_no_new_connection(listener: &UnixListener) {
    listener
        .set_nonblocking(true)
        .expect("make listener nonblocking");
    for _ in 0..50 {
        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(_) => panic!("client opened an unexpected additional connection"),
            Err(error) => panic!("unexpected listener failure: {error}"),
        }
    }
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
