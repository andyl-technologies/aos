//! Durable campaign-service bootstrap regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;

use crucible_campaign::{
    CampaignClient, CampaignClientError, CampaignName, CampaignPrincipal, CampaignServiceFailure,
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, GetCampaignRequest,
};
use tempfile::tempdir;

use crate::{LoopbackCampaignService, LoopbackCampaignTimeouts};

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
