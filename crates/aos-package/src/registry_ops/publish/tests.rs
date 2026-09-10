//! Tests for package publication orchestration and its exclusive authoring-clone lock.

use super::{
    apply_publish_sb_policy, publish_canonical_ability_output, required_publish_metadata,
    validate_release_publish_metadata, validate_release_publish_signing_identity,
};
use crate::ability_package::{collect_distinct_artifacts, decode_package_manifest};
use crate::config::ApmConfig;
use crate::registry::parse::ImageVerificationState;
use crate::registry::sb_certs::{RevokedSbCert, SbCert, SbCertsToml};
use crate::registry_ops::metadata::build_package_toml_with_documentation;
use crate::registry_ops::release::ReleaseStorePublish;
use crate::registry_ops::store_paths::introspect_store_path;
use crate::registry_ops::test_support::{
    init_authoring_clone, inspect_test_image, test_provenance_signer, write_direct_image_output,
};
use crate::types::{ApmSettings, ProfileScope};
use aos_core::output::Printer;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn ability_publication_accepts_a_transitive_self_referencing_closure() {
    let Ok(companion_path) = std::env::var("AOS_TEST_ABILITY_PACKAGE_SMOKE") else {
        return;
    };
    let manifest = fs::read(Path::new(&companion_path).join("package.json")).unwrap();
    let package = decode_package_manifest(&manifest).unwrap();
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

    let registry = TempDir::new().unwrap();
    init_authoring_clone(registry.path());
    let primary = introspect_store_path(&package.package.payload.store_path).unwrap();
    let package_toml = build_package_toml_with_documentation(
        "",
        package.package.name.as_str(),
        &package.package.version,
        "x86_64-linux",
        &primary,
        Some("Ability publication self-reference fixture"),
        None,
        Some("Apache-2.0"),
        Some("AOS test"),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let package_dir = registry.path().join("packages/a");
    fs::create_dir_all(&package_dir).unwrap();
    let package_path = package_dir.join("ability-package-smoke.toml");
    fs::write(&package_path, package_toml).unwrap();

    let mut signer = test_provenance_signer();
    publish_canonical_ability_output(
        registry.path(),
        "test",
        &companion_path,
        package.package.name.as_str(),
        &package.package.version,
        "x86_64-linux",
        &mut signer.signer,
        &Printer::new(0, true, false),
    )
    .await
    .unwrap();

    let published = fs::read_to_string(package_path).unwrap();
    let parsed = crate::registry::parse::parse_package_file(&published).unwrap();
    let ability = parsed.versions[0].platforms["x86_64-linux"]
        .ability
        .as_ref()
        .unwrap();
    let published_source = ability
        .artifacts
        .iter()
        .find(|published| published.store_path == package.package.source.store_path)
        .unwrap();
    let published_artifact = ability
        .artifacts
        .iter()
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

#[test]
fn secure_boot_publish_policy_distinguishes_unverified_active_and_revoked() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let mut image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
    let signer = "e".repeat(64);
    image.sb.signer_cert_sha256 = Some(signer.clone());
    image.delivery.uki.verification = ImageVerificationState::SignedUnverified;

    apply_publish_sb_policy(std::slice::from_mut(&mut image), None, false, false).unwrap();
    assert_eq!(
        image.delivery.uki.verification,
        ImageVerificationState::SignedUnverified
    );

    let active = SbCertsToml {
        active: vec![SbCert {
            id: "current".into(),
            cert_sha256: signer.clone(),
        }],
        ..SbCertsToml::default()
    };
    assert!(
        apply_publish_sb_policy(
            std::slice::from_mut(&mut image),
            Some(&active),
            false,
            false
        )
        .is_err()
    );
    apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&active), true, false).unwrap();
    assert_eq!(
        image.delivery.uki.verification,
        ImageVerificationState::PolicyVerified
    );

    let revoked = SbCertsToml {
        active: active.active,
        revoked: vec![RevokedSbCert {
            id: "current".into(),
            reason: Some("rotated".into()),
        }],
        ..SbCertsToml::default()
    };
    assert!(
        apply_publish_sb_policy(
            std::slice::from_mut(&mut image),
            Some(&revoked),
            true,
            false
        )
        .is_err()
    );
}

#[test]
fn secure_boot_publish_policy_enforces_opt_in_signed_uki_gate() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let mut image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();

    let error =
        apply_publish_sb_policy(std::slice::from_mut(&mut image), None, false, true).unwrap_err();
    assert!(error.to_string().contains("refuses unsigned UKIs"));

    let signer = "e".repeat(64);
    image.sb.signer_cert_sha256 = Some(signer.clone());
    let active = SbCertsToml {
        active: vec![SbCert {
            id: "staging".into(),
            cert_sha256: signer,
        }],
        ..SbCertsToml::default()
    };
    assert!(apply_publish_sb_policy(std::slice::from_mut(&mut image), None, true, true).is_err());
    assert!(
        apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&active), false, true)
            .is_err()
    );
    apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&active), true, true).unwrap();
    assert_eq!(
        image.delivery.uki.verification,
        ImageVerificationState::PolicyVerified
    );
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
        image_uki_paths: Vec::new(),
        bless: false,
        message: None,
        registry: "production".into(),
        signing_key_id: Some("initial".into()),
    };
    assert_eq!(publish.signing_key_id.as_deref(), Some("initial"));
    assert_eq!(publish.publish_signing_args(), (None, Some("initial")));
}
