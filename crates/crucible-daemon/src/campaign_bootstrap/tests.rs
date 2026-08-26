//! Durable campaign-service bootstrap regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AttemptResourceLimits, CampaignClient, CampaignClientError, CampaignLineage, CampaignMode,
    CampaignName, CampaignPolicy, CampaignPrincipal, CampaignSeed, CampaignServiceFailure,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse,
    ConfigurationId, DaemonEpoch, ExecutorCapabilityService, ExecutorCapabilitySet,
    ExecutorCapacityReport, ExecutorCompatibilityProfile, ExecutorControlService,
    ExecutorDescription, ExecutorMaterializationCapability, ExecutorResumeService, ExecutorService,
    ExecutorStatusService, ExplorerPolicy, FairnessPolicy, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, GetCampaignRequest, ProgressiveWideningPolicy, PuctPolicy,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, RetentionPolicy, ScenarioDefId,
    SubmitAttemptRequest, SubmitAttemptResponse, WatchExecutorCapacityRequest,
};
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, QemuChildProcessContract, QemuLaunchResourceRequirements,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};
use tempfile::tempdir;

use crate::{
    AllowAllAttemptAdmission, AttachCampaignRuntimeRequest, CampaignRuntimeAttachmentDisposition,
    CanonicalPlannerProcessConfig, ExecutorCapacity, ExecutorLoopbackEndpointConfig,
    ExecutorLoopbackServerConfig, LocalExecutorCapabilityService, LocalExecutorSupervisor,
    LoopbackCampaignService, LoopbackCampaignServiceError, LoopbackCampaignTimeouts,
    LoopbackExecutorTimeouts, MAX_EXECUTOR_REQUESTS_PER_CONNECTION, MemoryAssignmentLedger,
    PackagedQemuExecutorConfig, QemuAttemptCancellationSignal, QemuAttemptHostResourceFactory,
    QemuAttemptHostResourceOwner, serve_loopback_executor_component_connection_with_limits,
    serve_loopback_executor_component_once,
};

use super::*;

#[derive(Debug)]
struct UnusedPackagedHostFactory;

#[derive(Debug)]
struct UnusedPackagedHostOwner;

#[derive(Clone, Debug)]
struct UnusedPackagedCancellation;

impl QemuAttemptCancellationSignal for UnusedPackagedCancellation {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

impl QemuAttemptHostResourceFactory for UnusedPackagedHostFactory {
    type Owner = UnusedPackagedHostOwner;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        Err(unused_packaged_host_error())
    }
}

impl QemuAttemptHostResourceOwner for UnusedPackagedHostOwner {
    type CancellationSignal = UnusedPackagedCancellation;

    fn resource_limits(&self) -> AttemptResourceLimits {
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 1024 * 1024 * 1024, 50_000)
            .expect("packaged resource ceiling")
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Err(unused_packaged_host_error())
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(unused_packaged_host_error())
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        Ok(UnusedPackagedCancellation)
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Err(unused_packaged_host_error())
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn quarantine(&mut self) {}
}

fn unused_packaged_host_error() -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "use unused packaged bootstrap host",
        message: String::from("test does not execute a guest"),
    }
}

fn fixture() -> (tempfile::TempDir, CampaignLocalServiceConfig) {
    let directory = tempdir().expect("bootstrap directory");
    fs::set_permissions(directory.path(), Permissions::from_mode(0o700))
        .expect("secure bootstrap directory");
    let metadata = fs::metadata(directory.path()).expect("bootstrap metadata");
    let policy = directory.path().join("campaign-policy.toml");
    fs::write(
        &policy,
        format!(
            r#"schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = {}
group_id = {}
principal = "operator"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "create-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "attach-campaign-runtime"
campaign = "*"
"#,
            metadata.uid(),
            metadata.gid()
        ),
    )
    .expect("write policy");
    fs::set_permissions(&policy, Permissions::from_mode(0o600)).expect("secure policy mode");
    let endpoint = CampaignLoopbackEndpointConfig::new(
        directory.path().join("campaign.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("endpoint config");
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("state directory");
    fs::set_permissions(&state, Permissions::from_mode(0o700)).expect("secure state mode");
    let config = CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        CampaignLocalServiceMode::ReadWrite,
        CampaignLoopbackServerConfig::default(),
    )
    .expect("local service config");
    (directory, config)
}

fn write_component_authorities(path: &Path, planner: [u8; 32], debugger: [u8; 32]) {
    let mut bytes = Vec::with_capacity(COMPONENT_AUTHORITY_FILE_BYTES);
    bytes.extend_from_slice(COMPONENT_AUTHORITY_MAGIC);
    bytes.extend_from_slice(&planner);
    bytes.extend_from_slice(&debugger);
    fs::write(path, bytes).expect("write component authorities");
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .expect("secure component-authority mode");
}

fn runtime_config() -> CanonicalCampaignRuntimeConfig {
    named_runtime_config("attached")
}

fn named_runtime_config(name: &str) -> CanonicalCampaignRuntimeConfig {
    CanonicalCampaignRuntimeConfig::canonical_defaults(
        CampaignName::new(name).expect("campaign name"),
        CanonicalPlannerProcessConfig::new("/planner", Duration::from_secs(1))
            .expect("planner process configuration"),
    )
    .expect("runtime configuration")
}

fn create_runtime_campaign(repository: &Arc<CampaignRepository>, name: &str) -> CampaignLineage {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"bootstrap-scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("test", b"bootstrap-genesis"));
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
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
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening coefficient"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");
    repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    lineage
}

fn executor_capability_service(
    lineage: &CampaignLineage,
    epoch_byte: u8,
    store_label: &[u8],
) -> LocalExecutorCapabilityService<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    let epoch = DaemonEpoch::from_bytes([epoch_byte; 16]).expect("daemon epoch");
    let resources =
        AttemptResourceLimits::new(4, 1024 * 1024, 1024 * 1024, 10_000).expect("resources");
    let capabilities = ExecutorCapabilitySet::new(
        ExecutorCompatibilityProfile::from_lineage(lineage),
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        2,
        resources,
        BTreeSet::from([CampaignHash::derive("test", store_label)]),
    )
    .expect("executor capabilities");
    let description = crucible_campaign::ExecutorDescription::new(epoch, capabilities)
        .expect("executor description");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(2, 4, 1024 * 1024, 1024 * 1024, 10_000).expect("executor capacity"),
    );
    LocalExecutorCapabilityService::new(supervisor, description).expect("capability service")
}

fn executor_pair(lineage: &CampaignLineage) -> (UnixStream, thread::JoinHandle<()>) {
    let mut service = executor_capability_service(lineage, 0x41, b"store");
    let (client, mut server) = UnixStream::pair().expect("executor stream pair");
    let worker = thread::spawn(move || {
        serve_loopback_executor_component_once(
            &mut server,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve executor description");
    });
    (client, worker)
}

type TestExecutorService =
    LocalExecutorCapabilityService<MemoryAssignmentLedger, AllowAllAttemptAdmission>;

struct BlockingDescribeExecutorService {
    inner: TestExecutorService,
    observed: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
}

impl ExecutorService for BlockingDescribeExecutorService {
    type Error = <TestExecutorService as ExecutorService>::Error;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.inner.submit_attempt(request)
    }
}

impl ExecutorStatusService for BlockingDescribeExecutorService {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.inner.get_attempt_execution(request)
    }
}

impl ExecutorControlService for BlockingDescribeExecutorService {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.inner.checkpoint_attempt_execution(request)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.inner.cancel_attempt_execution(request)
    }
}

impl ExecutorResumeService for BlockingDescribeExecutorService {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.inner.resume_attempt_execution(request)
    }
}

impl ExecutorCapabilityService for BlockingDescribeExecutorService {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        if let Some(observed) = self.observed.take() {
            observed.send(()).expect("report blocked describe request");
        }
        self.release.recv().expect("release describe response");
        self.inner.describe_executor()
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        self.inner.watch_capacity(request)
    }
}

#[test]
fn runtime_attachment_requires_writable_component_authority_before_executor_io() {
    let (_directory, config) = fixture();
    let prepared = config
        .prepare()
        .expect("prepare service without authorities");
    let (executor, mut peer) = UnixStream::pair().expect("executor stream pair");
    assert!(matches!(
        prepared.prepare_runtime(executor, &runtime_config()),
        Err(CampaignLocalServiceError::RuntimeAuthorityUnavailable)
    ));
    peer.set_nonblocking(true).expect("nonblocking peer");
    let mut byte = [0_u8; 1];
    assert_eq!(peer.read(&mut byte).expect("closed executor peer"), 0);

    let (_directory, config) = fixture();
    let read_only = CampaignLocalServiceConfig::new(
        config.endpoint().clone(),
        config.state_directory(),
        config.policy_path(),
        CampaignLocalServiceMode::ReadOnly,
        config.server(),
    )
    .expect("read-only service configuration");
    let prepared = read_only.prepare().expect("prepare read-only service");
    let (executor, mut peer) = UnixStream::pair().expect("executor stream pair");
    assert!(matches!(
        prepared.prepare_runtime(executor, &runtime_config()),
        Err(CampaignLocalServiceError::RuntimeReadOnly)
    ));
    peer.set_nonblocking(true).expect("nonblocking peer");
    assert_eq!(peer.read(&mut byte).expect("closed executor peer"), 0);
}

#[test]
fn post_bind_attachment_rejects_missing_authority_and_read_only_before_executor_io() {
    let (directory, config) = fixture();
    let service = config.open().expect("bind service without authorities");
    let attachments = service.runtime_attachment_handle();
    let metadata = fs::metadata(directory.path()).expect("endpoint directory metadata");
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("missing-executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("missing executor endpoint contract");
    assert!(matches!(
        attachments.attach_endpoint(&endpoint, &runtime_config()),
        Err(CampaignLocalServiceError::RuntimeAuthorityUnavailable)
    ));
    drop(service);
    assert!(matches!(
        attachments.attached_campaigns(),
        Err(CampaignLocalServiceError::RuntimeAttachmentClosed)
    ));

    let (directory, config) = fixture();
    let read_only = CampaignLocalServiceConfig::new(
        config.endpoint().clone(),
        config.state_directory(),
        config.policy_path(),
        CampaignLocalServiceMode::ReadOnly,
        config.server(),
    )
    .expect("read-only service configuration");
    let service = read_only.open().expect("bind read-only service");
    let attachments = service.runtime_attachment_handle();
    let metadata = fs::metadata(directory.path()).expect("endpoint directory metadata");
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("missing-executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("missing executor endpoint contract");
    assert!(matches!(
        attachments.attach_endpoint(&endpoint, &runtime_config()),
        Err(CampaignLocalServiceError::RuntimeReadOnly)
    ));
    drop(service);
}

#[test]
fn multi_runtime_bind_rejects_an_empty_set_before_endpoint_mutation() {
    let (_directory, config) = fixture();
    let socket = config.endpoint().path().to_owned();
    let prepared = config.prepare().expect("prepare service");

    assert!(matches!(
        prepared.bind_with_runtimes(Vec::new()),
        Err(CampaignLocalServiceError::InvalidRuntimeCount)
    ));
    assert!(!socket.exists());
}

#[test]
fn multi_runtime_bind_sorts_unique_campaigns_and_joins_every_runtime() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let socket = config.endpoint().path().to_owned();
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "alpha");
    assert_eq!(
        create_runtime_campaign(&prepared.repository, "beta"),
        lineage
    );

    let (beta_executor, beta_server) = executor_pair(&lineage);
    let beta = prepared
        .prepare_runtime(beta_executor, &named_runtime_config("beta"))
        .expect("prepare beta runtime");
    let (alpha_executor, alpha_server) = executor_pair(&lineage);
    let alpha = prepared
        .prepare_runtime(alpha_executor, &named_runtime_config("alpha"))
        .expect("prepare alpha runtime");
    beta_server.join().expect("join beta executor server");
    alpha_server.join().expect("join alpha executor server");

    let service = prepared
        .bind_with_runtimes(vec![beta, alpha])
        .expect("bind runtime set");
    assert_eq!(
        service
            .runtime_attachment_handle()
            .attached_campaigns()
            .expect("attached campaigns")
            .iter()
            .map(CampaignName::as_str)
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    service.shutdown_handle().shutdown();
    service.serve().expect("serve and join runtime set");
    assert!(!socket.exists());
}

#[test]
fn packaged_executor_pool_serves_and_joins_two_campaign_runtimes() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let campaign_socket = config.endpoint().path().to_owned();
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "alpha");
    assert_eq!(
        create_runtime_campaign(&prepared.repository, "beta"),
        lineage
    );

    let metadata = fs::metadata(directory.path()).expect("packaged endpoint directory");
    let executor_endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("shared-executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("packaged executor endpoint");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-packaged-bootstrap-test",
        "/var/lib/crucible-packaged-bootstrap-test",
        "packaged-bootstrap-test",
        1,
        2,
        metadata.uid().checked_add(1).expect("child user ID"),
        metadata.gid().checked_add(1).expect("child group ID"),
        32,
        1024,
        Duration::from_secs(1),
    )
    .expect("packaged host configuration");
    let packaged_config = PackagedQemuExecutorConfig::new(
        BTreeSet::from([
            CampaignName::new("beta").expect("beta campaign"),
            CampaignName::new("alpha").expect("alpha campaign"),
        ]),
        executor_endpoint.clone(),
        ExecutorLoopbackServerConfig::default(),
        directory.path().join("executor-ledger"),
        directory.path().join("executor-checkpoints"),
        1024 * 1024,
        DaemonEpoch::from_bytes([0x61; 16]).expect("daemon epoch"),
        ExecutorCapacity::new(2, 2, 512 * 1024 * 1024, 1024 * 1024 * 1024, 50_000)
            .expect("executor capacity"),
        2,
        "x86_64",
        "deterministic-tcg-v1",
        CampaignHash::derive("crucible.test.shared-packaged-store.v1", b"bootstrap"),
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        host,
    )
    .expect("packaged executor configuration");
    let packaged = crate::packaged_qemu_executor::compose_packaged_qemu_executor(
        Arc::clone(&prepared.repository),
        ExecutorCompatibilityProfile::from_lineage(&lineage),
        lineage.scenario_content(),
        packaged_config,
        UnusedPackagedHostFactory,
    )
    .expect("compose shared packaged executor");
    let executor =
        AttachedPackagedQemuExecutor::start(packaged).expect("start shared packaged executor");

    let beta = prepared
        .prepare_runtime(
            executor_endpoint.connect().expect("connect beta runtime"),
            &named_runtime_config("beta"),
        )
        .expect("prepare beta runtime");
    let alpha = prepared
        .prepare_runtime(
            executor_endpoint.connect().expect("connect alpha runtime"),
            &named_runtime_config("alpha"),
        )
        .expect("prepare alpha runtime");
    let service = prepared
        .bind_with_runtimes_and_executor(vec![beta, alpha], executor)
        .expect("bind shared packaged executor pool");
    assert_eq!(
        service
            .runtime_attachment_handle()
            .attached_campaigns()
            .expect("attached campaigns")
            .iter()
            .map(CampaignName::as_str)
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    service.shutdown_handle().shutdown();
    service
        .serve()
        .expect("serve and join shared executor pool");
    assert!(!campaign_socket.exists());
    assert!(!executor_endpoint.path().exists());
}

#[test]
fn multi_runtime_bind_rejects_duplicate_campaigns_before_endpoint_mutation() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let socket = config.endpoint().path().to_owned();
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "attached");

    let (first_executor, first_server) = executor_pair(&lineage);
    let first = prepared
        .prepare_runtime(first_executor, &runtime_config())
        .expect("prepare first runtime");
    let (second_executor, second_server) = executor_pair(&lineage);
    let second = prepared
        .prepare_runtime(second_executor, &runtime_config())
        .expect("prepare second runtime");
    first_server.join().expect("join first executor server");
    second_server.join().expect("join second executor server");

    assert!(matches!(
        prepared.bind_with_runtimes(vec![first, second]),
        Err(CampaignLocalServiceError::DuplicateRuntimeCampaign)
    ));
    assert!(!socket.exists());
}

#[test]
fn post_bind_attachment_is_bounded_live_and_does_not_retain_service_ownership() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "dynamic");
    let service = prepared.bind().expect("bind service without runtimes");
    let attachments = service.runtime_attachment_handle();
    let shutdown = service.shutdown_handle();
    let server = thread::spawn(move || service.serve().expect("serve dynamic runtime"));

    let metadata = fs::metadata(directory.path()).expect("runtime endpoint directory metadata");
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("dynamic-executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("runtime executor endpoint");
    let managed = endpoint.bind().expect("bind runtime executor endpoint");
    let (listener, endpoint_guard) = managed.into_parts();
    let mut executor_service = executor_capability_service(&lineage, 0x42, b"dynamic-store");
    let executor_server = thread::spawn(move || {
        let _endpoint_guard = endpoint_guard;
        let (mut stream, _) = listener.accept().expect("accept runtime executor");
        serve_loopback_executor_component_connection_with_limits(
            &mut stream,
            &mut executor_service,
            LoopbackExecutorTimeouts::default(),
            MAX_EXECUTOR_REQUESTS_PER_CONNECTION,
        )
        .expect("serve runtime executor connection");
    });
    attachments
        .attach_endpoint(&endpoint, &named_runtime_config("dynamic"))
        .expect("attach runtime after bind");
    assert_eq!(
        attachments
            .attached_campaigns()
            .expect("attached campaign inventory"),
        [CampaignName::new("dynamic").expect("campaign name")]
    );

    let (duplicate, mut duplicate_peer) = UnixStream::pair().expect("duplicate executor pair");
    assert!(matches!(
        attachments.attach(duplicate, &named_runtime_config("dynamic")),
        Err(CampaignLocalServiceError::DuplicateRuntimeCampaign)
    ));
    duplicate_peer
        .set_nonblocking(true)
        .expect("nonblocking duplicate peer");
    let mut byte = [0_u8; 1];
    assert_eq!(
        duplicate_peer
            .read(&mut byte)
            .expect("duplicate executor closed before I/O"),
        0
    );

    shutdown.shutdown();
    server.join().expect("join campaign service");
    executor_server.join().expect("join executor server");
    assert!(matches!(
        attachments.attached_campaigns(),
        Err(CampaignLocalServiceError::RuntimeAttachmentClosed)
    ));

    let restarted = config
        .open()
        .expect("weak handle does not retain state lock");
    restarted.shutdown_handle().shutdown();
    restarted.serve().expect("serve restarted owner");
}

#[test]
fn authenticated_post_bind_attachment_replays_without_executor_io() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let socket = config.endpoint().path().to_owned();
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "dynamic");
    let prepared = prepared
        .with_runtime_control(named_runtime_config("dynamic").planner_process().clone())
        .expect("enable runtime control");
    let service = prepared.bind().expect("bind service without runtimes");
    let attachments = service.runtime_attachment_handle();
    let shutdown = service.shutdown_handle();
    let server = thread::spawn(move || service.serve().expect("serve dynamic runtime"));

    let metadata = fs::metadata(directory.path()).expect("runtime endpoint directory metadata");
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("dynamic-control-executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("runtime executor endpoint");
    let managed = endpoint.bind().expect("bind runtime executor endpoint");
    let (listener, endpoint_guard) = managed.into_parts();
    let mut executor_service = executor_capability_service(&lineage, 0x44, b"control-store");
    let executor_server = thread::spawn(move || {
        let _endpoint_guard = endpoint_guard;
        let (mut stream, _) = listener.accept().expect("accept runtime executor");
        serve_loopback_executor_component_connection_with_limits(
            &mut stream,
            &mut executor_service,
            LoopbackExecutorTimeouts::default(),
            MAX_EXECUTOR_REQUESTS_PER_CONNECTION,
        )
        .expect("serve runtime executor connection");
    });
    let request = AttachCampaignRuntimeRequest::new(
        CampaignPrincipal::new("operator").expect("principal"),
        CampaignName::new("dynamic").expect("campaign"),
        endpoint.path(),
    )
    .expect("runtime request");
    let loopback = LoopbackCampaignService::new(
        UnixStream::connect(&socket).expect("connect campaign service"),
    )
    .expect("campaign loopback");
    let attached = loopback
        .attach_campaign_runtime(&request)
        .expect("attach runtime");
    assert_eq!(
        attached.disposition(),
        CampaignRuntimeAttachmentDisposition::Attached
    );
    assert_eq!(attached.attached_runtime_count(), 1);

    let replayed = loopback
        .attach_campaign_runtime(&request)
        .expect("replay runtime attachment");
    assert_eq!(
        replayed.disposition(),
        CampaignRuntimeAttachmentDisposition::Replayed
    );
    assert_eq!(replayed.attached_runtime_count(), 1);
    let conflicting = AttachCampaignRuntimeRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        directory.path().join("other-executor.sock"),
    )
    .expect("conflicting request");
    assert!(matches!(
        loopback.attach_campaign_runtime(&conflicting),
        Err(LoopbackCampaignServiceError::Remote(
            CampaignServiceFailure::CommandReuse
        ))
    ));
    assert_eq!(
        attachments
            .attached_campaigns()
            .expect("attached campaign inventory"),
        [CampaignName::new("dynamic").expect("campaign")]
    );

    shutdown.shutdown();
    server.join().expect("join campaign service");
    executor_server.join().expect("join executor server");
}

#[test]
fn service_shutdown_waits_for_reserved_attachment_and_rejects_its_late_install() {
    let (directory, config) = fixture();
    let authority = directory.path().join("component-authority.bin");
    write_component_authorities(&authority, [0x31; 32], [0x73; 32]);
    let config = config
        .with_component_authority_path(&authority)
        .expect("component authority path");
    let prepared = config.prepare().expect("prepare service");
    let lineage = create_runtime_campaign(&prepared.repository, "closing");
    let service = prepared.bind().expect("bind service without runtimes");
    let attachments = service.runtime_attachment_handle();
    let shutdown = service.shutdown_handle();
    let (service_finished, service_result) = mpsc::channel();
    let server = thread::spawn(move || {
        let result = service.serve();
        service_finished
            .send(result)
            .expect("report campaign service result");
    });

    let (executor, mut executor_peer) = UnixStream::pair().expect("executor stream pair");
    let (request_observed, request_ready) = mpsc::channel();
    let (release_executor, executor_released) = mpsc::channel();
    let mut executor_service = BlockingDescribeExecutorService {
        inner: executor_capability_service(&lineage, 0x43, b"delayed-store"),
        observed: Some(request_observed),
        release: executor_released,
    };
    let executor_server = thread::spawn(move || {
        serve_loopback_executor_component_connection_with_limits(
            &mut executor_peer,
            &mut executor_service,
            LoopbackExecutorTimeouts::default(),
            MAX_EXECUTOR_REQUESTS_PER_CONNECTION,
        )
        .expect("serve delayed executor connection");
    });
    let attach_handle = attachments.clone();
    let attach =
        thread::spawn(move || attach_handle.attach(executor, &named_runtime_config("closing")));
    request_ready
        .recv_timeout(Duration::from_secs(1))
        .expect("attachment reserved before shutdown");

    shutdown.shutdown();
    assert!(matches!(
        service_result.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release_executor
        .send(())
        .expect("release delayed executor response");
    assert!(matches!(
        attach.join().expect("join attachment call"),
        Err(CampaignLocalServiceError::RuntimeAttachmentClosed)
    ));
    service_result
        .recv_timeout(Duration::from_secs(1))
        .expect("service exits after attachment settles")
        .expect("service result");
    server.join().expect("join campaign service thread");
    executor_server
        .join()
        .expect("join delayed executor server");
    assert!(matches!(
        attachments.attached_campaigns(),
        Err(CampaignLocalServiceError::RuntimeAttachmentClosed)
    ));
}

#[test]
fn read_only_mode_denies_policy_granted_mutation() {
    let (_directory, config) = fixture();
    let policy = Arc::new(
        load_policy(
            config.policy_path(),
            config.endpoint().owner_user_id(),
            config.endpoint().owner_group_id(),
        )
        .expect("load policy"),
    );
    let authorizer = CampaignLocalAuthorizer {
        policy,
        mode: CampaignLocalServiceMode::ReadOnly,
    };
    let principal = CampaignPrincipal::new("operator").expect("principal");
    let campaign = CampaignName::new("example").expect("campaign");
    let digest = CampaignHash::derive("campaign-bootstrap-read-only-test", b"request");
    assert_eq!(
        authorizer.authorize(
            &principal,
            CampaignServiceOperation::GetCampaign,
            &campaign,
            digest,
        ),
        Ok(())
    );
    assert_eq!(
        authorizer.authorize(
            &principal,
            CampaignServiceOperation::CreateCampaign,
            &campaign,
            digest,
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );
    assert_eq!(
        authorizer.authorize(
            &principal,
            CampaignServiceOperation::AttachCampaignRuntime,
            &campaign,
            digest,
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );
}

#[test]
fn durable_service_bootstrap_authenticates_policy_and_restarts_cleanly() {
    let (_directory, config) = fixture();
    let service = config.open().expect("open local service");
    let shutdown = service.shutdown_handle();
    let socket = config.endpoint().path().to_owned();
    let server = thread::spawn(move || service.serve().expect("serve local campaign service"));
    let stream = UnixStream::connect(&socket).expect("connect local campaign service");
    let client = CampaignClient::new(
        LoopbackCampaignService::with_timeouts(stream, LoopbackCampaignTimeouts::default())
            .expect("configure local campaign service"),
    );
    let request = GetCampaignRequest::new(
        CampaignPrincipal::new("operator").expect("principal"),
        CampaignName::new("absent").expect("campaign"),
    )
    .expect("get request");
    assert!(matches!(
        client.get_campaign(&request),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::NotFound
        ))
    ));
    shutdown.shutdown();
    let report = server.join().expect("join service");
    assert_eq!(report.accepted_connections(), 1);
    assert!(!socket.exists());

    let restarted = config.open().expect("restart local service");
    restarted.shutdown_handle().shutdown();
    restarted.serve().expect("serve pre-stopped restart");
}

#[test]
fn repository_lock_excludes_a_second_socket_incarnation() {
    let (directory, config) = fixture();
    let first = config.open().expect("first local service");
    let metadata = fs::metadata(directory.path()).expect("directory metadata");
    let second_endpoint = CampaignLoopbackEndpointConfig::new(
        directory.path().join("campaign-second.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("second endpoint");
    let second = CampaignLocalServiceConfig::new(
        second_endpoint,
        config.state_directory(),
        config.policy_path(),
        config.mode(),
        config.server(),
    )
    .expect("second config");
    assert!(matches!(
        second.open(),
        Err(CampaignLocalServiceError::StateInUse)
    ));
    assert!(!second.endpoint().path().exists());
    drop(first);
}

#[test]
fn prepared_owner_imports_verified_artifacts_before_socket_bind() {
    let (_directory, config) = fixture();
    let prepared = config.prepare().expect("prepare local service");
    assert!(!config.endpoint().path().exists());
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::StateInUse)
    ));

    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let configuration = prepared
        .import_configuration(&scenario, &crucible::Schedule::empty())
        .expect("import verified configuration");
    let generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
    let generator_id = prepared
        .import_generator(&generator)
        .expect("import verified generator");
    assert_ne!(configuration.content_id(), generator_id.content_id());
    assert!(!config.endpoint().path().exists());

    let service = prepared.bind().expect("bind prepared service");
    assert!(config.endpoint().path().exists());
    service.shutdown_handle().shutdown();
    service.serve().expect("serve pre-stopped service");
}

#[test]
fn component_authorities_are_authenticated_before_repository_open() {
    let (directory, config) = fixture();
    let authority_path = directory.path().join("component-authorities.bin");
    write_component_authorities(&authority_path, [0x31; 32], [0x73; 32]);
    let configured = config
        .clone()
        .with_component_authority_path(&authority_path)
        .expect("component-authority path");
    assert_eq!(
        configured.component_authority_path(),
        Some(authority_path.as_path())
    );

    let prepared = configured.prepare().expect("prepare with authorities");
    assert!(!configured.endpoint().path().exists());
    let service = prepared.bind().expect("bind authority-backed service");
    service.shutdown_handle().shutdown();
    service.serve().expect("serve pre-stopped service");
}

#[test]
fn malformed_component_authorities_fail_before_repository_or_socket_mutation() {
    let (directory, config) = fixture();
    let authority_path = directory.path().join("component-authorities.bin");
    write_component_authorities(&authority_path, [0x31; 32], [0x31; 32]);
    let configured = config
        .clone()
        .with_component_authority_path(&authority_path)
        .expect("component-authority path");
    assert!(matches!(
        configured.prepare(),
        Err(CampaignLocalServiceError::InvalidComponentAuthorityFile)
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());

    write_component_authorities(&authority_path, [0; 32], [0x73; 32]);
    assert!(matches!(
        configured.prepare(),
        Err(CampaignLocalServiceError::InvalidComponentAuthorityFile)
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());

    write_component_authorities(&authority_path, [0x31; 32], [0x73; 32]);
    fs::set_permissions(&authority_path, Permissions::from_mode(0o640))
        .expect("expose authority file");
    assert!(matches!(
        configured.prepare(),
        Err(CampaignLocalServiceError::InvalidComponentAuthorityFile)
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());

    fs::set_permissions(&authority_path, Permissions::from_mode(0o600))
        .expect("restore authority mode");
    let target = directory.path().join("component-authority-target.bin");
    fs::rename(&authority_path, &target).expect("move authority target");
    symlink(&target, &authority_path).expect("component-authority symlink");
    assert!(matches!(
        configured.prepare(),
        Err(CampaignLocalServiceError::InvalidComponentAuthorityFile)
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());
}

#[test]
fn component_authority_path_uses_the_deployment_path_profile() {
    let (_directory, config) = fixture();
    assert!(matches!(
        config.with_component_authority_path("relative-authorities.bin"),
        Err(CampaignLocalServiceError::InvalidComponentAuthorityPath)
    ));
}

#[test]
fn prepared_read_only_owner_rejects_artifact_import() {
    let (_directory, config) = fixture();
    let read_only = CampaignLocalServiceConfig::new(
        config.endpoint().clone(),
        config.state_directory(),
        config.policy_path(),
        CampaignLocalServiceMode::ReadOnly,
        config.server(),
    )
    .expect("read-only config");
    let prepared = read_only.prepare().expect("prepare read-only service");
    let generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
    assert!(matches!(
        prepared.import_generator(&generator),
        Err(CampaignLocalServiceError::ArtifactImportReadOnly)
    ));
    assert!(!read_only.endpoint().path().exists());
}

#[test]
fn policy_and_state_ownership_fail_before_socket_bind() {
    let (directory, config) = fixture();
    fs::set_permissions(config.policy_path(), Permissions::from_mode(0o620))
        .expect("writable policy");
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::InvalidPolicyFile)
    ));
    assert!(!config.endpoint().path().exists());

    fs::set_permissions(config.policy_path(), Permissions::from_mode(0o600))
        .expect("restore policy");
    fs::set_permissions(config.state_directory(), Permissions::from_mode(0o770))
        .expect("writable state");
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::InvalidStateDirectory)
    ));
    assert!(!config.endpoint().path().exists());

    fs::set_permissions(config.state_directory(), Permissions::from_mode(0o700))
        .expect("restore state");
    let objects = config.state_directory().join(OBJECT_DIRECTORY);
    fs::create_dir(&objects).expect("objects directory");
    fs::set_permissions(&objects, Permissions::from_mode(0o750))
        .expect("exposed objects directory");
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::InvalidStateSubdirectory)
    ));
    assert!(!config.endpoint().path().exists());
    fs::remove_dir(&objects).expect("remove exposed objects directory");

    let target = directory.path().join("policy-target");
    fs::write(&target, b"not policy").expect("policy target");
    let redirected = directory.path().join("redirected-policy.toml");
    symlink(&target, &redirected).expect("policy symlink");
    let symlink_config = CampaignLocalServiceConfig::new(
        config.endpoint().clone(),
        config.state_directory(),
        redirected,
        config.mode(),
        config.server(),
    )
    .expect("symlink config");
    assert!(matches!(
        symlink_config.open(),
        Err(CampaignLocalServiceError::InvalidPolicyFile)
    ));
    assert!(!config.endpoint().path().exists());
}

#[test]
fn malformed_or_oversized_policy_is_read_only_failure() {
    let (_directory, config) = fixture();
    fs::write(config.policy_path(), b"schema = [").expect("malformed policy");
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::Policy(
            UnixPeerCampaignPolicyLoadError::Toml { .. }
        ))
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());

    fs::write(
        config.policy_path(),
        vec![b' '; MAX_CAMPAIGN_POLICY_BYTES + 1],
    )
    .expect("oversized policy");
    assert!(matches!(
        config.open(),
        Err(CampaignLocalServiceError::Policy(
            UnixPeerCampaignPolicyLoadError::TooLarge
        ))
    ));
    assert!(!config.state_directory().join(OBJECT_DIRECTORY).exists());
    assert!(!config.state_directory().join(REF_DIRECTORY).exists());
    assert!(!config.endpoint().path().exists());
}
