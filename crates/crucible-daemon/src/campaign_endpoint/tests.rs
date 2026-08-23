//! Managed endpoint lifecycle regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::fs::{self, Permissions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};

use super::*;

fn endpoint_fixture() -> (tempfile::TempDir, CampaignLoopbackEndpointConfig) {
    let directory = tempfile::tempdir().expect("endpoint directory");
    fs::set_permissions(directory.path(), Permissions::from_mode(0o750))
        .expect("secure endpoint directory mode");
    let metadata = fs::metadata(directory.path()).expect("endpoint directory metadata");
    let config = CampaignLoopbackEndpointConfig::new(
        directory.path().join("campaign.sock"),
        metadata.uid(),
        metadata.gid(),
        0o660,
    )
    .expect("endpoint config");
    (directory, config)
}

#[test]
fn managed_endpoint_is_single_owner_restart_safe_and_exactly_cleaned() {
    let (_directory, config) = endpoint_fixture();
    let managed = config.bind().expect("bind managed endpoint");
    let metadata = fs::symlink_metadata(config.path()).expect("bound socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.mode() & 0o777, 0o660);
    assert!(matches!(
        config.bind(),
        Err(CampaignLoopbackEndpointError::EndpointInUse)
    ));
    UnixStream::connect(config.path()).expect("connect managed endpoint");

    drop(managed);
    assert!(!config.path().exists());
    let restarted = config.bind().expect("restart managed endpoint");
    assert!(config.path().exists());
    drop(restarted);
    assert!(!config.path().exists());
}

#[test]
fn managed_endpoint_recovers_only_a_same_owner_stale_socket() {
    let (_directory, config) = endpoint_fixture();
    let stale = UnixListener::bind(config.path()).expect("bind stale socket");
    drop(stale);
    assert!(config.path().exists());

    let managed = config.bind().expect("recover stale socket");
    UnixStream::connect(config.path()).expect("connect recovered endpoint");
    drop(managed);

    fs::write(config.path(), b"not a socket").expect("foreign regular path");
    assert!(matches!(
        config.bind(),
        Err(CampaignLoopbackEndpointError::InvalidStalePath)
    ));
    assert_eq!(
        fs::read(config.path()).expect("regular path retained"),
        b"not a socket"
    );
}

#[test]
fn managed_endpoint_cleanup_never_removes_a_replacement_path() {
    let (_directory, config) = endpoint_fixture();
    let managed = config.bind().expect("bind managed endpoint");
    fs::remove_file(config.path()).expect("unlink active socket name");
    fs::write(config.path(), b"replacement").expect("install replacement path");

    drop(managed);

    assert_eq!(
        fs::read(config.path()).expect("replacement retained"),
        b"replacement"
    );
}

#[test]
fn campaign_and_executor_endpoints_share_a_directory_without_sharing_authority() {
    let directory = tempfile::tempdir().expect("component endpoint directory");
    fs::set_permissions(directory.path(), Permissions::from_mode(0o750))
        .expect("secure component directory mode");
    let metadata = fs::metadata(directory.path()).expect("component directory metadata");
    let campaign = CampaignLoopbackEndpointConfig::new(
        directory.path().join("campaign.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("campaign endpoint config");
    let executor = ExecutorLoopbackEndpointConfig::new(
        directory.path().join("executor.sock"),
        metadata.uid(),
        metadata.gid(),
        0o600,
    )
    .expect("executor endpoint config");

    let campaign_listener = campaign.bind().expect("bind campaign endpoint");
    let executor_listener = executor.bind().expect("bind executor endpoint");
    assert!(matches!(
        campaign.bind(),
        Err(CampaignLoopbackEndpointError::EndpointInUse)
    ));
    assert!(matches!(
        executor.bind(),
        Err(ExecutorLoopbackEndpointError::EndpointInUse)
    ));
    UnixStream::connect(campaign.path()).expect("connect campaign endpoint");
    UnixStream::connect(executor.path()).expect("connect executor endpoint");

    drop(campaign_listener);
    assert!(!campaign.path().exists());
    assert!(executor.path().exists());
    drop(executor_listener);
    assert!(!executor.path().exists());
}

#[test]
fn endpoint_rejects_writable_or_redirected_namespaces_before_bind() {
    let (directory, config) = endpoint_fixture();
    fs::set_permissions(directory.path(), Permissions::from_mode(0o770))
        .expect("make endpoint namespace group writable");
    assert!(matches!(
        config.bind(),
        Err(CampaignLoopbackEndpointError::ParentNamespaceWritable)
    ));
    assert!(!config.path().exists());

    fs::set_permissions(directory.path(), Permissions::from_mode(0o750))
        .expect("restore endpoint directory");
    let target = directory.path().join("target");
    fs::write(&target, b"target").expect("symlink target");
    symlink(&target, config.path()).expect("endpoint symlink");
    assert!(matches!(
        config.bind(),
        Err(CampaignLoopbackEndpointError::InvalidStalePath)
    ));
    assert!(
        fs::symlink_metadata(config.path())
            .expect("symlink retained")
            .file_type()
            .is_symlink()
    );

    fs::remove_file(config.path()).expect("remove endpoint symlink");
    let lock_path = directory.path().join(CAMPAIGN_ENDPOINT_LOCK_FILE);
    fs::remove_file(&lock_path).expect("remove prior endpoint lock");
    symlink(&target, &lock_path).expect("endpoint lock symlink");
    assert!(matches!(
        config.bind(),
        Err(CampaignLoopbackEndpointError::Io { .. })
    ));
    assert!(
        fs::symlink_metadata(lock_path)
            .expect("lock symlink retained")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn endpoint_configuration_rejects_invalid_path_mode_and_owner() {
    let (directory, config) = endpoint_fixture();
    assert!(matches!(
        CampaignLoopbackEndpointConfig::new("relative.sock", 1, 1, 0o600),
        Err(CampaignLoopbackEndpointError::InvalidPath)
    ));
    assert!(matches!(
        CampaignLoopbackEndpointConfig::new("/tmp/../tmp/campaign.sock", 1, 1, 0o600),
        Err(CampaignLoopbackEndpointError::InvalidPath)
    ));
    let oversized = format!("/tmp/{}.sock", "a".repeat(100));
    assert!(matches!(
        CampaignLoopbackEndpointConfig::new(oversized, 1, 1, 0o600),
        Err(CampaignLoopbackEndpointError::InvalidPath)
    ));
    assert!(matches!(
        CampaignLoopbackEndpointConfig::new(directory.path().join("zero.sock"), 1, 1, 0),
        Err(CampaignLoopbackEndpointError::InvalidSocketMode)
    ));
    let wrong_owner = CampaignLoopbackEndpointConfig::new(
        config.path(),
        config.owner_user_id().wrapping_add(1),
        config.owner_group_id(),
        0o600,
    )
    .expect("wrong-owner contract is structurally valid");
    assert!(matches!(
        wrong_owner.bind(),
        Err(CampaignLoopbackEndpointError::ParentOwnershipMismatch)
    ));
    assert!(!config.path().exists());
}
