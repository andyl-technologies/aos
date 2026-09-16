//! Tests for package publication orchestration and its exclusive authoring-clone lock.

use super::{
    publish_package_contract, required_publish_metadata, validate_release_publish_metadata,
    validate_release_publish_signing_identity,
};
use crate::config::ApmConfig;
use crate::package_contract::{
    collect_distinct_artifacts, decode_package_manifest, read_package_manifest, retained_artifacts,
};
use crate::registry::release::RegistryReleaseEntry;
use crate::registry_ops::metadata::build_package_toml_with_documentation;
use crate::registry_ops::release::ReleaseStorePublish;
use crate::registry_ops::store_paths::introspect_store_path;
use crate::registry_ops::test_support::{
    init_authoring_clone, test_provenance_signer, write_test_roster,
};
use crate::types::{ApmSettings, ProfileScope};
use aos_core::output::Printer;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn package_contract_publication_requires_the_committed_roster_binding() {
    let registry = TempDir::new().unwrap();
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

    let error = publish_package_contract(
        registry.path(),
        "test",
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo-contract",
        "demo",
        "1.0.0",
        "x86_64-linux",
        &crate::registry_ops::PackageContractSelectorRegistry::new(&[]),
        &mut signer.signer,
        &Printer::new(0, true, false),
    )
    .await
    .unwrap_err();

    assert!(
        format!("{error:#}").contains("revoked in keys.toml"),
        "{error:#}"
    );
}

#[tokio::test]
async fn package_contract_publication_accepts_a_transitive_self_referencing_closure() {
    let Ok(companion_path) = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE") else {
        return;
    };
    let payload_path = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE_PAYLOAD").unwrap();
    let provider_path = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE_PROVIDER").unwrap();
    let source_path = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE_SOURCE").unwrap();
    let projection =
        aos_ability_validate::decode_package_projection(&fs::read(&companion_path).unwrap())
            .unwrap();
    assert!(projection.qualification.package_probe.is_some());

    let registry = TempDir::new().unwrap();
    init_authoring_clone(registry.path());
    let primary = introspect_store_path(&payload_path).unwrap();
    let source = introspect_store_path(&source_path).unwrap();
    let package_toml = build_package_toml_with_documentation(
        "",
        projection.package.name.as_str(),
        &projection.package.version,
        "x86_64-linux",
        &primary,
        Some("Ability publication self-reference fixture"),
        None,
        Some("Apache-2.0"),
        Some("AOS test"),
        false,
        None,
        &[],
        Some(&source),
        None,
        None,
    )
    .unwrap();
    let package_dir = registry.path().join("packages/a");
    fs::create_dir_all(&package_dir).unwrap();
    let package_path = package_dir.join("ability-package-smoke.toml");
    fs::write(&package_path, package_toml).unwrap();

    let entries = [
        release_entry("out", &payload_path),
        release_entry(crate::types::PACKAGE_CONTRACT_OUTPUT, &companion_path),
        RegistryReleaseEntry {
            id: "provider".to_string(),
            name: "ability-package-smoke-provider".to_string(),
            version: "1.0.0".to_string(),
            platform: "x86_64-linux".to_string(),
            output: "out".to_string(),
            store_path: provider_path.clone(),
        },
    ];
    let selectors = crate::registry_ops::PackageContractSelectorRegistry::new(&entries);
    let mut signer = test_provenance_signer();
    publish_package_contract(
        registry.path(),
        "test",
        &companion_path,
        projection.package.name.as_str(),
        &projection.package.version,
        "x86_64-linux",
        &selectors,
        &mut signer.signer,
        &Printer::new(0, true, false),
    )
    .await
    .unwrap();

    let published = fs::read_to_string(package_path).unwrap();
    let parsed = crate::registry::parse::parse_package_file(&published).unwrap();
    let contract = parsed.versions[0].platforms["x86_64-linux"]
        .contract
        .as_ref()
        .unwrap();
    assert_eq!(
        parsed.versions[0].platforms["x86_64-linux"].named_outputs
            [crate::types::PACKAGE_CONTRACT_OUTPUT],
        companion_path
    );
    let manifest = read_package_manifest(&contract.document.store_path).unwrap();
    let package = decode_package_manifest(&manifest).unwrap();
    assert!(package.qualification.package_probe.is_some());
    let mut fixture_artifacts = collect_distinct_artifacts(&package)
        .unwrap()
        .into_iter()
        .filter(|artifact| {
            Path::new(&artifact.store_path)
                .join("transitive-dependency")
                .is_file()
        })
        .collect::<Vec<_>>();
    assert_eq!(fixture_artifacts.len(), 1);
    let artifact = fixture_artifacts.remove(0);
    let dependency_path =
        fs::read_to_string(Path::new(&artifact.store_path).join("transitive-dependency")).unwrap();
    let dependency_path = dependency_path.trim();

    assert_ne!(dependency_path, artifact.store_path);
    assert_eq!(
        fs::read_to_string(Path::new(dependency_path).join("self-reference"))
            .unwrap()
            .trim(),
        dependency_path
    );
    let published_source = retained_artifacts(contract)
        .find(|published| published.store_path == package.package.source.store_path)
        .unwrap();
    let published_artifact = retained_artifacts(contract)
        .find(|published| published.store_path == artifact.store_path)
        .unwrap();
    let dependency = published_artifact
        .closure
        .iter()
        .find(|member| member.store_path == dependency_path)
        .unwrap();
    let dependency_hash = dependency_path
        .rsplit_once('/')
        .unwrap()
        .1
        .split_once('-')
        .unwrap()
        .0;

    assert!(
        published_source
            .closure
            .iter()
            .any(|member| member.store_path == package.package.source.store_path)
    );
    assert_eq!(
        published_source.closure_digest,
        package.package.source.closure.to_string()
    );
    assert!(
        !dependency
            .references
            .iter()
            .any(|hash| hash == dependency_hash)
    );
}

fn release_entry(output: &str, store_path: &str) -> RegistryReleaseEntry {
    RegistryReleaseEntry {
        id: output.to_string(),
        name: "ability-package-smoke".to_string(),
        version: "1.0.0".to_string(),
        platform: "x86_64-linux".to_string(),
        output: output.to_string(),
        store_path: store_path.to_string(),
    }
}

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
