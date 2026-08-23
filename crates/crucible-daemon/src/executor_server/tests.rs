#![allow(clippy::disallowed_methods, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::{Duration, Instant};

use crucible_campaign::{
    AttemptResourceLimits, CampaignHash, CampaignLineage, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, ConfigurationArtifact, ConfigurationId, DaemonEpoch,
    ExecutorCapabilityService, ExecutorCapabilitySet, ExecutorCompatibilityProfile,
    ExecutorControlService, ExecutorDescription, ExecutorMaterializationCapability,
    ExecutorResumeService, ExecutorService, ExecutorStatusService, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse,
    ScenarioArtifact, ScenarioDefId, SubmitAttemptRequest, SubmitAttemptResponse,
    WatchExecutorCapacityRequest,
};

use super::{
    ExecutorLoopbackServer, ExecutorLoopbackServerConfig, ExecutorLoopbackServerConfigError,
    UnixPeerExecutorIdentity,
};
use crate::{
    AllowAllAttemptAdmission, LocalExecutorPoolService, LoopbackExecutorService,
    LoopbackExecutorTimeouts, MAX_EXECUTOR_LISTENER_WORKERS, MAX_EXECUTOR_PENDING_CONNECTIONS,
    MAX_EXECUTOR_REQUESTS_PER_CONNECTION, MemoryAssignmentLedger,
};

#[derive(Clone)]
struct DescriptionOnlyService {
    description: ExecutorDescription,
}

impl ExecutorService for DescriptionOnlyService {
    type Error = Infallible;

    fn submit_attempt(
        &mut self,
        _request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        unreachable!("description-only fixture received SubmitAttempt")
    }
}

impl ExecutorStatusService for DescriptionOnlyService {
    fn get_attempt_execution(
        &mut self,
        _request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        unreachable!("description-only fixture received GetAttemptExecution")
    }
}

impl ExecutorControlService for DescriptionOnlyService {
    fn checkpoint_attempt_execution(
        &mut self,
        _request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        unreachable!("description-only fixture received CheckpointAttemptExecution")
    }

    fn cancel_attempt_execution(
        &mut self,
        _request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        unreachable!("description-only fixture received CancelAttemptExecution")
    }
}

impl ExecutorResumeService for DescriptionOnlyService {
    fn resume_attempt_execution(
        &mut self,
        _request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        unreachable!("description-only fixture received ResumeAttemptExecution")
    }
}

impl ExecutorCapabilityService for DescriptionOnlyService {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        Ok(self.description.clone())
    }

    fn watch_capacity(
        &mut self,
        _request: &WatchExecutorCapacityRequest,
    ) -> Result<crucible_campaign::ExecutorCapacityReport, Self::Error> {
        unreachable!("description-only fixture received WatchCapacity")
    }
}

#[test]
fn fixed_listener_serves_multiple_authenticated_requests_and_joins() {
    let directory = tempfile::tempdir().expect("executor listener directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("bind executor listener");
    let description = description();
    let server = ExecutorLoopbackServer::new(
        listener,
        DescriptionOnlyService {
            description: description.clone(),
        },
        current_identity(),
        test_config(2, 4, 8),
    )
    .expect("executor server");
    let shutdown = server.shutdown_handle();
    let join = thread::spawn(move || server.serve());

    let stream = UnixStream::connect(&socket).expect("connect executor client");
    let mut client = LoopbackExecutorService::new(stream).expect("executor client");
    assert_eq!(
        client.describe_executor().expect("first description"),
        description
    );
    assert_eq!(
        client.describe_executor().expect("second description"),
        description
    );
    drop(client);
    wait_until(Duration::from_secs(2), || {
        shutdown.active_connections() == 0
    });
    shutdown.shutdown();

    let report = join
        .join()
        .expect("join executor listener")
        .expect("serve executor listener");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
    assert_eq!(report.service_failures(), 0);
}

#[test]
fn wrong_kernel_peer_is_rejected_before_component_dispatch() {
    let directory = tempfile::tempdir().expect("executor listener directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("bind executor listener");
    let identity = current_identity();
    let denied =
        UnixPeerExecutorIdentity::new(identity.user_id().wrapping_add(1), identity.group_id());
    let server = ExecutorLoopbackServer::new(
        listener,
        DescriptionOnlyService {
            description: description(),
        },
        denied,
        test_config(1, 1, 1),
    )
    .expect("executor server");
    let shutdown = server.shutdown_handle();
    let join = thread::spawn(move || server.serve());

    let stream = UnixStream::connect(&socket).expect("connect denied peer");
    let mut client = LoopbackExecutorService::new(stream).expect("executor client");
    assert!(client.describe_executor().is_err());
    wait_until(Duration::from_secs(2), || {
        shutdown.active_connections() == 0
    });
    shutdown.shutdown();

    let report = join
        .join()
        .expect("join executor listener")
        .expect("serve executor listener");
    assert_eq!(report.accepted_connections(), 1);
    assert_eq!(report.peer_rejections(), 1);
    assert_eq!(report.completed_connections(), 0);
}

#[test]
fn fairness_limit_closes_only_after_the_last_complete_response() {
    let directory = tempfile::tempdir().expect("executor listener directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("bind executor listener");
    let expected = description();
    let server = ExecutorLoopbackServer::new(
        listener,
        DescriptionOnlyService {
            description: expected.clone(),
        },
        current_identity(),
        test_config(1, 1, 1),
    )
    .expect("executor server");
    let shutdown = server.shutdown_handle();
    let join = thread::spawn(move || server.serve());

    let stream = UnixStream::connect(&socket).expect("connect executor client");
    let mut client = LoopbackExecutorService::new(stream).expect("executor client");
    assert_eq!(
        client.describe_executor().expect("bounded response"),
        expected
    );
    assert!(client.describe_executor().is_err());
    wait_until(Duration::from_secs(2), || {
        shutdown.active_connections() == 0
    });
    shutdown.shutdown();

    let report = join
        .join()
        .expect("join executor listener")
        .expect("serve executor listener");
    assert_eq!(report.completed_connections(), 1);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn sticky_shutdown_interrupts_an_idle_authenticated_connection() {
    let directory = tempfile::tempdir().expect("executor listener directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("bind executor listener");
    let server = ExecutorLoopbackServer::new(
        listener,
        DescriptionOnlyService {
            description: description(),
        },
        current_identity(),
        test_config(1, 1, 8),
    )
    .expect("executor server");
    let shutdown = server.shutdown_handle();
    let join = thread::spawn(move || server.serve());

    let _idle = UnixStream::connect(&socket).expect("connect idle peer");
    wait_until(Duration::from_secs(2), || {
        shutdown.active_connections() == 1
    });
    shutdown.shutdown();

    let report = join
        .join()
        .expect("join executor listener")
        .expect("serve executor listener");
    assert_eq!(report.accepted_connections(), 1);
    assert!(shutdown.is_shutdown());
    assert_eq!(shutdown.active_connections(), 0);
}

#[test]
fn fixed_workers_and_pending_queue_reject_excess_and_drain_on_shutdown() {
    let directory = tempfile::tempdir().expect("executor listener directory");
    let socket = directory.path().join("executor.sock");
    let listener = UnixListener::bind(&socket).expect("bind executor listener");
    let server = ExecutorLoopbackServer::new(
        listener,
        DescriptionOnlyService {
            description: description(),
        },
        current_identity(),
        test_config(1, 1, 8),
    )
    .expect("executor server");
    let shutdown = server.shutdown_handle();
    let join = thread::spawn(move || server.serve());

    let mut active = UnixStream::connect(&socket).expect("active executor peer");
    wait_until(Duration::from_secs(2), || {
        shutdown.active_connections() == 1
    });
    let queued = UnixStream::connect(&socket).expect("queued executor peer");
    thread::sleep(Duration::from_millis(30));
    let mut rejected = UnixStream::connect(&socket).expect("rejected executor peer");
    rejected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("rejected read timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(rejected.read(&mut byte).expect("capacity close"), 0);

    shutdown.shutdown();
    active
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("active read timeout");
    assert_eq!(active.read(&mut byte).expect("shutdown close"), 0);
    drop(queued);

    let report = join
        .join()
        .expect("join executor listener")
        .expect("serve executor listener");
    assert_eq!(report.accepted_connections(), 3);
    assert_eq!(report.capacity_rejections(), 1);
    assert_eq!(report.completed_connections(), 0);
    assert_eq!(report.peer_rejections(), 0);
    assert_eq!(report.protocol_failures(), 0);
}

#[test]
fn listener_configuration_enforces_every_static_bound() {
    let timeouts = LoopbackExecutorTimeouts::default();
    assert_eq!(
        ExecutorLoopbackServerConfig::new(0, 1, 1, Duration::from_millis(1), timeouts),
        Err(ExecutorLoopbackServerConfigError::InvalidWorkerCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(
            MAX_EXECUTOR_LISTENER_WORKERS + 1,
            1,
            1,
            Duration::from_millis(1),
            timeouts,
        ),
        Err(ExecutorLoopbackServerConfigError::InvalidWorkerCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(1, 0, 1, Duration::from_millis(1), timeouts),
        Err(ExecutorLoopbackServerConfigError::InvalidPendingCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(
            1,
            MAX_EXECUTOR_PENDING_CONNECTIONS + 1,
            1,
            Duration::from_millis(1),
            timeouts,
        ),
        Err(ExecutorLoopbackServerConfigError::InvalidPendingCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(1, 1, 0, Duration::from_millis(1), timeouts),
        Err(ExecutorLoopbackServerConfigError::InvalidRequestCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(
            1,
            1,
            MAX_EXECUTOR_REQUESTS_PER_CONNECTION + 1,
            Duration::from_millis(1),
            timeouts,
        ),
        Err(ExecutorLoopbackServerConfigError::InvalidRequestCount)
    );
    assert_eq!(
        ExecutorLoopbackServerConfig::new(1, 1, 1, Duration::ZERO, timeouts),
        Err(ExecutorLoopbackServerConfigError::InvalidPollInterval)
    );
}

#[test]
fn bounded_worker_pool_service_satisfies_the_listener_capability_boundary() {
    fn require_listener_service<S>()
    where
        S: ExecutorCapabilityService
            + ExecutorControlService
            + ExecutorResumeService
            + Clone
            + Send
            + 'static,
    {
    }

    require_listener_service::<
        LocalExecutorPoolService<MemoryAssignmentLedger, AllowAllAttemptAdmission>,
    >();
}

fn current_identity() -> UnixPeerExecutorIdentity {
    UnixPeerExecutorIdentity::new(
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

fn test_config(workers: usize, pending: usize, requests: usize) -> ExecutorLoopbackServerConfig {
    ExecutorLoopbackServerConfig::new(
        workers,
        pending,
        requests,
        Duration::from_millis(1),
        LoopbackExecutorTimeouts::new(Duration::from_secs(2), Duration::from_secs(2))
            .expect("executor timeouts"),
    )
    .expect("executor listener config")
}

fn description() -> ExecutorDescription {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario"));
    let scenario_content = ScenarioArtifact::new(scenario, 1, b"scenario-body".to_vec())
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact id");
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("test", b"genesis"));
    let genesis_content = ConfigurationArtifact::new(
        scenario,
        scenario_content,
        genesis,
        1,
        b"genesis-body".to_vec(),
    )
    .expect("configuration artifact")
    .id()
    .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let resources =
        AttemptResourceLimits::new(2, 1 << 20, 1 << 20, 10_000).expect("resource ceilings");
    let capabilities = ExecutorCapabilitySet::new(
        ExecutorCompatibilityProfile::from_lineage(&lineage),
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        2,
        resources,
        BTreeSet::from([CampaignHash::derive("test", b"store")]),
    )
    .expect("executor capabilities");
    let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("daemon epoch");
    ExecutorDescription::new(epoch, capabilities).expect("executor description")
}

fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
