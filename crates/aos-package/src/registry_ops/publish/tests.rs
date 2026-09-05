//! Tests for package publication orchestration and its exclusive authoring-clone lock.

use super::{
    apply_publish_sb_policy, required_publish_metadata, validate_release_publish_metadata,
    validate_release_publish_signing_identity,
};
use crate::config::ApmConfig;
use crate::registry::parse::ImageVerificationState;
use crate::registry::sb_certs::{RevokedSbCert, SbCert, SbCertsToml};
use crate::registry_ops::release::ReleaseStorePublish;
use crate::registry_ops::test_support::{inspect_test_image, write_direct_image_output};
use crate::types::{ApmSettings, ProfileScope};
use tempfile::TempDir;

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
