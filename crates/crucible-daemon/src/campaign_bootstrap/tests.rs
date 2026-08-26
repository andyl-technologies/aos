//! Durable campaign-service bootstrap regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    AttemptResourceLimits, CampaignClient, CampaignClientError, CampaignLineage, CampaignMode,
    CampaignName, CampaignPolicy, CampaignPrincipal, CampaignSeed, CampaignServiceFailure,
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, ConfigurationId, DaemonEpoch,
    ExecutorCapabilitySet, ExecutorCompatibilityProfile, ExecutorMaterializationCapability,
    ExplorerPolicy, FairnessPolicy, GetCampaignRequest, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, ScenarioDefId,
};
use tempfile::tempdir;

use crate::{
    AllowAllAttemptAdmission, CanonicalPlannerProcessConfig, ExecutorCapacity,
    LocalExecutorCapabilityService, LocalExecutorSupervisor, LoopbackCampaignService,
    LoopbackCampaignTimeouts, LoopbackExecutorTimeouts, MemoryAssignmentLedger,
    serve_loopback_executor_component_once,
};

use super::*;

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

fn executor_pair(lineage: &CampaignLineage) -> (UnixStream, thread::JoinHandle<()>) {
    let epoch = DaemonEpoch::from_bytes([0x41; 16]).expect("daemon epoch");
    let resources =
        AttemptResourceLimits::new(4, 1024 * 1024, 1024 * 1024, 10_000).expect("resources");
    let capabilities = ExecutorCapabilitySet::new(
        ExecutorCompatibilityProfile::from_lineage(lineage),
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        2,
        resources,
        BTreeSet::from([CampaignHash::derive("test", b"store")]),
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
    let mut service =
        LocalExecutorCapabilityService::new(supervisor, description).expect("capability service");
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
            .runtimes
            .iter()
            .map(|runtime| runtime.campaign().as_str())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    service.shutdown_handle().shutdown();
    service.serve().expect("serve and join runtime set");
    assert!(!socket.exists());
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
