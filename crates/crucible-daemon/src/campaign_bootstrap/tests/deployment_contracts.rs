//! Deployment-store, authority, and policy bootstrap regressions.

use super::*;

#[test]
fn external_store_rejects_a_nondurable_immutable_backend() {
    let blobs = Arc::new(MemoryBlobBackend::new("volatile-campaign", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    assert!(matches!(
        CampaignLocalRepositoryStore::new(blobs, refs),
        Err(CampaignLocalServiceError::InvalidRepositoryStore)
    ));
}

#[test]
fn external_store_rejects_a_nondurable_ref_backend() {
    let directory = tempdir().expect("external store directory");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "durable-campaign",
        directory.path().join("objects"),
    ));
    let refs = Arc::new(MemoryRefBackend::new());
    assert!(matches!(
        CampaignLocalRepositoryStore::new(blobs, refs),
        Err(CampaignLocalServiceError::InvalidRepositoryStore)
    ));
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
    let generator = CandidateGeneratorSpec::new(
        crucible_campaign::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("generator");
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
fn default_sqlite_store_reopens_and_rejects_a_loose_object_layout() {
    let (_directory, config) = fixture();
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let configuration = {
        let prepared = config.prepare().expect("SQLite-backed campaign owner");
        prepared
            .import_configuration(&scenario, &crucible::Schedule::empty())
            .expect("durable configuration")
    };
    assert!(
        config
            .state_directory()
            .join(OBJECT_DIRECTORY)
            .join("objects.sqlite3")
            .is_file()
    );

    let reopened = config.prepare().expect("restarted SQLite-backed owner");
    assert_eq!(
        reopened
            .import_configuration(&scenario, &crucible::Schedule::empty())
            .expect("reopened authenticated configuration"),
        configuration
    );
    drop(reopened);

    for marker in ["objects", ".inventory-admin"] {
        let (_legacy_directory, legacy_config) = fixture();
        let object_root = legacy_config.state_directory().join(OBJECT_DIRECTORY);
        fs::create_dir_all(object_root.join(marker)).expect("legacy directory-leaf marker");
        fs::set_permissions(&object_root, Permissions::from_mode(0o700))
            .expect("secure legacy object root");
        assert!(matches!(
            legacy_config.prepare(),
            Err(CampaignLocalServiceError::InvalidRepositoryStore)
        ));
        assert!(!object_root.join("objects.sqlite3").exists());
    }
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
    let generator = CandidateGeneratorSpec::new(
        crucible_campaign::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("generator");
    assert!(matches!(
        prepared.import_generator(&generator),
        Err(CampaignLocalServiceError::ArtifactImportReadOnly)
    ));
    let maintenance = CampaignStoreMaintenanceConfig::new(Duration::from_millis(100), 1, 1, 1)
        .expect("maintenance policy");
    assert!(matches!(
        prepared.with_store_maintenance(maintenance),
        Err(CampaignLocalServiceError::StoreMaintenanceReadOnly)
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
