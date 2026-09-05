//! Tests for attestation metadata and content digests binding published artifacts.

use super::publish_config_attestation_meta;
use crate::registry_ops::provenance::publish_config_provenance_artifact;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    TEST_PROVENANCE_REGISTRY, config_module_fixture, config_module_fixture_with_base,
    signed_provenance_statement, test_provenance_signer,
};
use crate::types::ConfigOutputMeta;

#[test]
fn config_attestation_binds_config_base_lib_and_expose_independently() {
    let payload = StorePathInfo {
        path: "/nix/store/0000000000000000000000000000000a-web-1".to_string(),
        nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        nar_size: 1,
        references: vec![],
        closure_size: 1,
    };
    let mut module = config_module_fixture();
    module.config_output.nar_hash =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    module.evaluation_base_lib = Some(ConfigOutputMeta {
        store_path: "/nix/store/0000000000000000000000000000000c-base-lib".to_string(),
        nar_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        nar_size: 1,
        references: vec![],
    });
    let original = publish_config_attestation_meta(
        "web",
        "1",
        "x86_64-linux",
        &payload,
        &module,
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
    )
    .expect("derive combined attestation");
    let signer = test_provenance_signer();
    let artifact = publish_config_provenance_artifact(
        TEST_PROVENANCE_REGISTRY,
        "web",
        "1",
        "x86_64-linux",
        &payload,
        None,
        &module,
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        &original,
        &signer.signer,
    )
    .expect("sign combined config provenance");
    let statement = signed_provenance_statement(&artifact);
    let subjects = statement["subject"].as_array().expect("subjects");
    for (name, digest) in [
        (
            "aos:expose-manifest:web:1:x86_64-linux",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
        (
            "aos:config-module:web:1:x86_64-linux",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        (
            "aos:config-base-lib:web:1:x86_64-linux",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
    ] {
        let subject = subjects
            .iter()
            .find(|subject| subject["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing signed subject {name}"));
        assert_eq!(subject["digest"]["sha256"].as_str(), Some(digest));
    }

    module.config_output.nar_hash =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
    let changed_config = publish_config_attestation_meta(
        "web",
        "1",
        "x86_64-linux",
        &payload,
        &module,
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
    )
    .expect("derive config-tampered attestation");
    assert_ne!(original.measurement, changed_config.measurement);

    module.config_output.nar_hash =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    module
        .evaluation_base_lib
        .as_mut()
        .expect("base lib")
        .nar_hash =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let changed_base = publish_config_attestation_meta(
        "web",
        "1",
        "x86_64-linux",
        &payload,
        &module,
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
    )
    .expect("derive base-tampered attestation");
    assert_ne!(original.measurement, changed_base.measurement);

    let changed_expose = publish_config_attestation_meta(
        "web",
        "1",
        "x86_64-linux",
        &payload,
        &config_module_fixture_with_base(),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
    )
    .expect("derive expose-tampered attestation");
    assert_ne!(original.measurement, changed_expose.measurement);
}

#[test]
fn package_attestation_measurement_changes_when_manifest_digest_changes() {
    let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let first = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        &crate::package_attestation::package_manifest_digest_bytes(br#"{"network":"private"}"#),
    );
    let second = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        &crate::package_attestation::package_manifest_digest_bytes(br#"{"network":"host"}"#),
    );

    assert_ne!(first, second);
}
