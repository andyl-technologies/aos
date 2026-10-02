//! Tests for package publication orchestration and its exclusive authoring-clone lock.

use super::{
    required_publish_metadata, validate_release_publish_metadata,
    validate_release_publish_signing_identity,
};
use crate::config::ApmConfig;
use crate::registry_ops::release::ReleaseStorePublish;
use crate::types::{ApmSettings, ProfileScope};

#[test]
fn publish_distribution_metadata_rejects_missing_empty_and_legacy_values() {
    assert!(required_publish_metadata(None, "--description", "No description").is_err());
    assert!(required_publish_metadata(Some("  "), "--license", "unknown").is_err());
    assert!(required_publish_metadata(Some("UNKNOWN"), "--maintainer", "unknown").is_err());
    assert_eq!(
        required_publish_metadata(Some("  Andyl, Inc.  "), "--maintainer", "unknown").unwrap(),
        "Andyl, Inc."
    );
}

#[test]
fn release_store_path_metadata_is_validated_for_dry_run_plans() {
    assert!(validate_release_publish_metadata(None, None, None, None).is_ok());
    assert!(
        validate_release_publish_metadata(Some("/nix/store/example"), None, None, None).is_err()
    );
    assert!(
        validate_release_publish_metadata(
            Some("/nix/store/example"),
            Some("Example package"),
            Some("MIT"),
            Some("Andyl, Inc."),
        )
        .is_ok()
    );
}

#[test]
fn release_store_path_requires_and_preserves_roster_identity() {
    assert!(validate_release_publish_signing_identity(None, None).is_ok());
    let error = validate_release_publish_signing_identity(Some("/nix/store/example-package"), None)
        .unwrap_err();
    assert!(format!("{error:#}").contains("requires --key-id"));
    assert!(
        validate_release_publish_signing_identity(
            Some("/nix/store/example-package"),
            Some("initial"),
        )
        .is_ok()
    );

    let publish = ReleaseStorePublish {
        config: ApmConfig {
            settings: ApmSettings::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        },
        store_path: "/nix/store/example-package".into(),
        name: None,
        version: None,
        platform: None,
        description: Some("Example package".into()),
        homepage: None,
        license: Some("MIT".into()),
        maintainer: Some("Andyl, Inc.".into()),
        sysroot: false,
        previous: None,
        source_drv: None,
        image_payload_paths: Vec::new(),
        image_disk_paths: Vec::new(),
        image_info_paths: Vec::new(),
        image_formats: Vec::new(),
        image_contract_schemas: Vec::new(),
        bless: false,
        message: None,
        registry: "production".into(),
        signing_key_id: Some("initial".into()),
    };
    assert_eq!(publish.signing_key_id.as_deref(), Some("initial"));
    assert_eq!(publish.publish_signing_args(), (None, Some("initial")));
}

#[tokio::test]
async fn native_release_publication_requires_an_active_committed_signer() {
    use crate::registry_ops::test_support::{
        init_authoring_clone, test_provenance_signer, write_test_roster,
    };

    let registry = tempfile::tempdir().unwrap();
    init_authoring_clone(registry.path());
    let mut signer = test_provenance_signer();
    write_test_roster(
        registry.path(),
        signer.signer.key_id.as_str(),
        &signer.trusted_key,
        &[signer.signer.key_id.as_str()],
    )
    .unwrap();
    crate::testutil::git(registry.path(), &["add", "keys.toml"]);
    crate::testutil::git(registry.path(), &["commit", "-m", "revoke publisher"]);
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: Vec::new(),
        scope: ProfileScope::User,
    };

    let error = super::publish_canonical_release_entry(
        &config,
        registry.path(),
        "test",
        "/nix/store/00000000000000000000000000000000-example",
        "example",
        "1",
        "x86_64-linux",
        "Native package",
        None,
        "Apache-2.0",
        "AOS test",
        &mut signer.signer,
        &aos_core::output::Printer::new(0, true, false),
    )
    .await
    .unwrap_err();

    assert!(
        format!("{error:#}").contains("revoked in keys.toml"),
        "{error:#}"
    );
}
