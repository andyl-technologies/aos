//! Tests for package catalog TOML construction and platform metadata recording.

use super::{
    build_package_toml, build_package_toml_with_documentation, record_config_module_platform_fields,
};
use crate::registry_ops::attestation::{package_nar_root_digest, publish_config_attestation_meta};
use crate::registry_ops::mac::{PublishExposeManifest, PublishMacProfileManifest};
use crate::registry_ops::provenance::{bind_documentation_provenance, publish_provenance_ref};
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    config_module_fixture, config_module_fixture_with_base, inspect_test_image,
    rewrite_test_image_parent, verity_expose_manifest, write_direct_image_output,
};
use crate::types::{
    AttestationMeta, DocumentationArtifactMeta, ExposeMeta, FEATURE_ATTESTATION_V1,
    FEATURE_CAPABILITY_ROUTES_V1, FEATURE_CONFIG_MODULE_V1, FEATURE_CONFIG_V1,
    FEATURE_EBPF_NET_POLICY_V1, FEATURE_EXPOSE_ARTIFACT_V1, FEATURE_EXPOSE_V1,
    FEATURE_MAC_PROFILE_V1, FEATURE_NETWORK_POLICY_V1, FEATURE_PACKAGE_DOCUMENTATION_V1,
    FEATURE_PERMISSIONS_V1, FEATURE_RELOAD_V1, FEATURE_REQUIRES_V1, PACKAGE_META_FORMAT,
    PermissionsMeta, RecoveryUkiEntry, SbatEntry, UkiSlot,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn record_config_module_emits_table_and_feature() {
    let mut table = toml::map::Map::new();
    record_config_module_platform_fields(&mut table, "firewall", &config_module_fixture())
        .expect("records config module");
    assert!(table.contains_key("config_module"));
    let features = table
        .get("requires-features")
        .and_then(toml::Value::as_array)
        .expect("feature array");
    assert!(features.contains(&toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string())));
    // Idempotent feature append.
    record_config_module_platform_fields(&mut table, "firewall", &config_module_fixture())
        .expect("re-records");
    let features = table
        .get("requires-features")
        .and_then(toml::Value::as_array)
        .expect("feature array");
    assert_eq!(
        features
            .iter()
            .filter(|f| **f == toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string()))
            .count(),
        1
    );
}

#[test]
fn build_package_toml_round_trips_config_output_hash_and_base_lib_binding() {
    let info = StorePathInfo {
        path: "/nix/store/0000000000000000000000000000000d-firewall-1".to_string(),
        nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        nar_size: 1024,
        references: vec![],
        closure_size: 1024,
    };
    let module = config_module_fixture_with_base();
    let attestation =
        publish_config_attestation_meta("firewall", "1", "x86_64-linux", &info, &module, None)
            .expect("config attestation");
    let content = build_package_toml(
        "",
        "firewall",
        "1",
        "x86_64-linux",
        &info,
        Some("Firewall configuration"),
        None,
        Some("Apache-2.0"),
        Some("Andyl, Inc."),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        Some(&module),
        Some(&attestation),
    )
    .expect("render config-module package metadata");

    let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
        .expect("parse package metadata")
        .expect("matching platform");
    let parsed_module = parsed.config_module.expect("config module metadata");
    assert_eq!(
        parsed_module.config_output.nar_hash,
        module.config_output.nar_hash
    );
    assert_eq!(
        parsed_module
            .evaluation_base_lib
            .expect("base-lib binding")
            .nar_hash,
        module
            .evaluation_base_lib
            .expect("fixture base-lib binding")
            .nar_hash
    );
    assert!(
        parsed
            .requires_features
            .iter()
            .any(|feature| { feature == FEATURE_CONFIG_MODULE_V1 })
    );
    assert_eq!(parsed.attestation.provenance, attestation.provenance);
}

#[test]
fn build_package_toml_binds_documentation_as_a_signed_platform_artifact() {
    let info = StorePathInfo {
        path: "/nix/store/0000000000000000000000000000000d-firewall-1".to_string(),
        nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        nar_size: 1024,
        references: vec![],
        closure_size: 1024,
    };
    let documentation = DocumentationArtifactMeta {
        format: aos_doc_model::DOCUMENT_FORMAT.to_string(),
        store_path: "/nix/store/0000000000000000000000000000000e-firewall-docs.json".to_string(),
        nar_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        nar_size: 512,
        document_sha256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        document_size: 384,
        semantic_schema_sha256:
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        system_module_nar_hash: None,
        references: vec![],
    };
    let attestation = AttestationMeta {
        root_digest: Some(info.nar_hash.clone()),
        provenance: Some("provenance/firewall/1/x86_64-linux.jsonl".to_string()),
        measurement: Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        ),
        ..AttestationMeta::default()
    };

    let content = build_package_toml_with_documentation(
        "",
        "firewall",
        "1",
        "x86_64-linux",
        &info,
        Some("Firewall configuration"),
        None,
        Some("Apache-2.0"),
        Some("Andyl, Inc."),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&documentation),
        Some(&attestation),
    )
    .expect("render documentation-bearing package metadata");

    let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
        .expect("parse package metadata")
        .expect("matching platform");
    assert_eq!(parsed.documentation, Some(documentation));
    assert!(
        parsed
            .requires_features
            .iter()
            .any(|feature| feature == FEATURE_PACKAGE_DOCUMENTATION_V1)
    );
    let documented_attestation = bind_documentation_provenance(
        attestation,
        "firewall",
        "x86_64-linux",
        parsed
            .documentation
            .as_ref()
            .expect("parsed documentation metadata"),
    )
    .expect("bind documentation provenance");
    assert_eq!(
        parsed.attestation.provenance,
        documented_attestation.provenance
    );
}

#[test]
fn build_package_toml_new() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-curl-8.5.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec!["ref1".into(), "ref2".into()],
        closure_size: 5242880,
    };
    let content = build_package_toml(
        "",
        "curl",
        "8.5.0",
        "x86_64-linux",
        &info,
        Some("URL transfer tool"),
        Some("https://curl.se"),
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert!(content.contains("name = \"curl\""));
    assert!(content.contains("version = \"8.5.0\""));
    assert!(content.contains("x86_64-linux"));
    // Output content bindings live in the store/ graph, not the TOML
    // (RFC-0005).
    assert!(!content.contains("nar_hash = \"sha256:deadbeef\""));
    assert!(!content.contains("nar_size"));
    assert!(content.contains("source_drv = \"\""));
    assert!(content.contains("source_nar_hash = \"\""));
}

#[test]
fn build_package_toml_refreshes_package_metadata() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-curl-8.5.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let existing = r#"
[package]
name = "curl"
description = "No description"
license = "unknown"
maintainer = "unknown"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/old-curl-8.5.0"
source_drv = ""
source_nar_hash = ""
"#;

    let content = build_package_toml(
        existing,
        "curl",
        "8.5.0",
        "x86_64-linux",
        &info,
        Some("Command line tool and library for transferring data with URLs"),
        Some("https://curl.se"),
        Some("curl"),
        Some("Andyl, Inc."),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(content.contains(
        "description = \"Command line tool and library for transferring data with URLs\""
    ));
    assert!(content.contains("homepage = \"https://curl.se\""));
    assert!(content.contains("license = \"curl\""));
    assert!(content.contains("maintainer = \"Andyl, Inc.\""));
    assert!(!content.contains("No description"));
    assert!(!content.contains("unknown"));
}

#[test]
fn build_package_toml_records_source_deriver() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-curl-8.5.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let source_info = StorePathInfo {
        path: "/nix/store/drv123-curl-8.5.0.drv".into(),
        nar_hash: "sha256:source".into(),
        nar_size: 4096,
        references: vec![],
        closure_size: 4096,
    };
    let content = build_package_toml(
        "",
        "curl",
        "8.5.0",
        "x86_64-linux",
        &info,
        Some("URL transfer tool"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        Some(&source_info),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert!(content.contains("source_drv = \"/nix/store/drv123-curl-8.5.0.drv\""));
    assert!(content.contains("source_nar_hash = \"sha256:source\""));
}

#[test]
fn build_package_toml_records_expose_manifest_metadata() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let artifact = StorePathInfo {
        path: "/nix/store/artifacthash111-expose-webapp".into(),
        nar_hash: "sha256:artifact".into(),
        nar_size: 2048,
        references: vec![],
        closure_size: 2048,
    };
    let mut permissions = PermissionsMeta {
        network: Some(crate::types::NetworkPermission::PrivateOutbound),
        tcp_bind: vec![8080],
        tcp_connect: vec![443],
        capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
        ..PermissionsMeta::default()
    };
    permissions.confinement = Some(permissions.computed_confinement());
    let manifest = PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec![
                "webapp.service".into(),
                "aos-pkg-webapp.slice".into(),
                "aos-pkg-webapp-mac.service".into(),
                "aos-pkg-webapp-ebpf.service".into(),
            ],
            images: Vec::new(),
            requires: vec!["zlib".into()],
            config: crate::types::ExposeConfigMeta {
                artifacts: vec![crate::types::ConfigArtifactMeta {
                    name: "env".into(),
                    path: "/etc/aos/packages/webapp/config.env".into(),
                    format: crate::types::ConfigArtifactFormat::Env,
                    required: vec!["TOKEN".into()],
                    optional: Vec::new(),
                    units: vec!["webapp.service".into()],
                    reload: crate::types::ConfigReloadPolicy::Reload,
                }],
                credentials: Vec::new(),
            },
            provides: vec![crate::types::ProvidedCapabilityMeta {
                name: "data".into(),
                kind: crate::types::CapabilityKind::Directory,
                path: Some("/var/lib/webapp/data".into()),
                unit: None,
            }],
            uses: vec![crate::types::RequiredCapabilityMeta {
                provider: "zlib".into(),
                name: "headers".into(),
                kind: crate::types::CapabilityKind::Directory,
                unit: "webapp.service".into(),
            }],
        },
        permissions,
        mac: Some(PublishMacProfileManifest {
            version: 1,
            package: "webapp".into(),
            backend: "selinux".into(),
            security_label: "aos-pkg-webapp".into(),
            default_deny: true,
            profile_path: Some("mac/selinux/aos_x2dpkg_x2dwebapp.pp".into()),
        }),
        _kernel: None,
        _firewall: None,
        _confinement: None,
    };
    let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
        br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
    );
    let expected_root_digest = package_nar_root_digest(&info.nar_hash);
    let expected_measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        &expected_root_digest,
        &manifest_digest,
    );

    let content = build_package_toml(
        "",
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Web application"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        Some(&manifest),
        Some(&artifact),
        Some(&manifest_digest),
        None,
        None,
    )
    .unwrap();

    let rendered: toml::Value = toml::from_str(&content).unwrap();
    let platform = rendered
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.get("x86_64-linux"))
        .unwrap();
    assert_eq!(
        platform.get("min-format").and_then(toml::Value::as_integer),
        Some(i64::from(PACKAGE_META_FORMAT))
    );
    assert_eq!(
        platform
            .get("requires-features")
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap(),
        vec![
            FEATURE_EXPOSE_V1,
            FEATURE_EXPOSE_ARTIFACT_V1,
            FEATURE_PERMISSIONS_V1,
            FEATURE_NETWORK_POLICY_V1,
            FEATURE_REQUIRES_V1,
            FEATURE_CONFIG_V1,
            FEATURE_RELOAD_V1,
            FEATURE_CAPABILITY_ROUTES_V1,
            FEATURE_EBPF_NET_POLICY_V1,
            FEATURE_MAC_PROFILE_V1,
            FEATURE_ATTESTATION_V1,
        ]
    );
    assert_eq!(
        platform.get("root_digest").and_then(toml::Value::as_str),
        Some(expected_root_digest.as_str())
    );
    assert_eq!(
        platform.get("measurement").and_then(toml::Value::as_str),
        Some(expected_measurement.as_str())
    );
    assert_eq!(
        platform
            .get("references")
            .and_then(|references| references.get("min-format"))
            .and_then(toml::Value::as_integer),
        Some(i64::from(PACKAGE_META_FORMAT))
    );
    assert_eq!(
        platform
            .get("expose")
            .and_then(|expose| expose.get("target"))
            .and_then(toml::Value::as_str),
        Some("aos-pkg-webapp.target")
    );
    assert_eq!(
        platform
            .get("expose_artifact")
            .and_then(|artifact| artifact.get("store_path"))
            .and_then(toml::Value::as_str),
        Some("/nix/store/artifacthash111-expose-webapp")
    );
    assert_eq!(
        platform
            .get("permissions")
            .and_then(|permissions| permissions.get("network"))
            .and_then(toml::Value::as_str),
        Some("private-outbound")
    );
    assert_eq!(
        platform
            .get("permissions")
            .and_then(|permissions| permissions.get("tcp-bind"))
            .and_then(toml::Value::as_array)
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(toml::Value::as_integer)
                    .collect::<Vec<_>>()
            }),
        Some(vec![8080])
    );
    assert_eq!(
        platform
            .get("permissions")
            .and_then(|permissions| permissions.get("tcp-connect"))
            .and_then(toml::Value::as_array)
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(toml::Value::as_integer)
                    .collect::<Vec<_>>()
            }),
        Some(vec![443])
    );
    assert_eq!(
        platform
            .get("permissions")
            .and_then(|permissions| permissions.get("confinement"))
            .and_then(|confinement| confinement.get("label"))
            .and_then(toml::Value::as_str),
        Some(
            "sandboxed-with-holes (network:private-outbound, tcp-bind:8080, tcp-connect:443, capability:CAP_NET_BIND_SERVICE)",
        )
    );

    let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed.expose.as_ref().map(|expose| expose.target.as_str()),
        Some("aos-pkg-webapp.target")
    );
    assert_eq!(
        parsed
            .expose_artifact
            .as_ref()
            .map(|artifact| artifact.store_path.as_str()),
        Some("/nix/store/artifacthash111-expose-webapp")
    );
    assert_eq!(
        parsed.permissions.network,
        Some(crate::types::NetworkPermission::PrivateOutbound)
    );
    assert_eq!(parsed.permissions.tcp_bind, vec![8080]);
    assert_eq!(parsed.permissions.tcp_connect, vec![443]);
}

#[test]
fn build_package_toml_detects_ebpf_feature_from_package_name() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let artifact = StorePathInfo {
        path: "/nix/store/artifacthash111-expose-webapp".into(),
        nar_hash: "sha256:artifact".into(),
        nar_size: 2048,
        references: vec![],
        closure_size: 2048,
    };
    let manifest = PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec![
                "webapp.service".into(),
                "aos-pkg-webapp.slice".into(),
                "aos-pkg-webapp-ebpf.service".into(),
            ],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        },
        permissions: PermissionsMeta::default(),
        mac: None,
        _kernel: None,
        _firewall: None,
        _confinement: None,
    };
    let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
        br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
    );

    let content = build_package_toml(
        "",
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Web application"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        Some(&manifest),
        Some(&artifact),
        Some(&manifest_digest),
        None,
        None,
    )
    .unwrap();

    let rendered: toml::Value = toml::from_str(&content).unwrap();
    let features = rendered
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.get("x86_64-linux"))
        .and_then(|platform| platform.get("requires-features"))
        .and_then(toml::Value::as_array)
        .map(|features| {
            features
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert!(features.contains(&FEATURE_EBPF_NET_POLICY_V1));
}

#[test]
fn build_package_toml_rejects_expose_manifest_without_artifact() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let manifest = PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec!["webapp.service".into()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        },
        permissions: PermissionsMeta::default(),
        mac: None,
        _kernel: None,
        _firewall: None,
        _confinement: None,
    };

    let err = build_package_toml(
        "",
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Web application"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        Some(&manifest),
        None,
        None,
        None,
        None,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("requires rendered expose artifact"));
}

#[test]
fn build_package_toml_records_expose_artifact_metadata() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let artifact = StorePathInfo {
        path: "/nix/store/artifacthash111-expose-webapp".into(),
        nar_hash: "sha256:artifact".into(),
        nar_size: 2048,
        references: vec![],
        closure_size: 2048,
    };
    let manifest = PublishExposeManifest {
        expose: ExposeMeta {
            target: "aos-pkg-webapp.target".into(),
            units: vec!["webapp.service".into()],
            images: Vec::new(),
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        },
        permissions: PermissionsMeta::default(),
        mac: None,
        _kernel: None,
        _firewall: None,
        _confinement: None,
    };
    let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
        br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
    );
    let expected_root_digest = package_nar_root_digest(&info.nar_hash);
    let expected_measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        &expected_root_digest,
        &manifest_digest,
    );

    let content = build_package_toml(
        "",
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Web application"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        Some(&manifest),
        Some(&artifact),
        Some(&manifest_digest),
        None,
        None,
    )
    .unwrap();

    let rendered: toml::Value = toml::from_str(&content).unwrap();
    let platform = rendered
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.get("x86_64-linux"))
        .unwrap();
    let features = platform
        .get("requires-features")
        .and_then(toml::Value::as_array)
        .map(|features| {
            features
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert!(features.contains(&FEATURE_EXPOSE_ARTIFACT_V1));
    assert!(features.contains(&FEATURE_NETWORK_POLICY_V1));
    assert!(features.contains(&FEATURE_ATTESTATION_V1));
    assert_eq!(
        platform
            .get("expose_artifact")
            .and_then(|artifact| artifact.get("store_path"))
            .and_then(toml::Value::as_str),
        Some("/nix/store/artifacthash111-expose-webapp")
    );
    assert_eq!(
        platform.get("root_digest").and_then(toml::Value::as_str),
        Some(expected_root_digest.as_str())
    );
    assert_eq!(platform.get("root_hash"), None);
    assert_eq!(platform.get("root_hash_sig"), None);
    let expected_provenance =
        publish_provenance_ref("webapp", "x86_64-linux", &expected_measurement).unwrap();
    assert_eq!(
        platform.get("provenance").and_then(toml::Value::as_str),
        Some(expected_provenance.as_str())
    );
    assert_eq!(
        platform.get("measurement").and_then(toml::Value::as_str),
        Some(expected_measurement.as_str())
    );

    let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed
            .expose_artifact
            .as_ref()
            .map(|artifact| artifact.store_path.as_str()),
        Some("/nix/store/artifacthash111-expose-webapp")
    );
    assert_eq!(
        parsed.attestation.root_digest.as_deref(),
        Some(expected_root_digest.as_str())
    );
    assert_eq!(
        parsed.attestation.provenance.as_deref(),
        Some(expected_provenance.as_str())
    );
    assert_eq!(
        parsed.attestation.measurement.as_deref(),
        Some(expected_measurement.as_str())
    );
}

#[test]
fn build_package_toml_records_package_attestation_measurement() {
    let info = StorePathInfo {
        path: "/nix/store/abc123-webapp-1.0.0".into(),
        nar_hash: "sha256:deadbeef".into(),
        nar_size: 1048576,
        references: vec![],
        closure_size: 5242880,
    };
    let artifact = StorePathInfo {
        path: "/nix/store/artifacthash111-expose-webapp".into(),
        nar_hash: "sha256:artifact".into(),
        nar_size: 2048,
        references: vec![],
        closure_size: 2048,
    };
    let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let manifest = verity_expose_manifest(root_hash);
    let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
        br#"{"expose":{"target":"aos-pkg-webapp.target"},"permissions":{}}"#,
    );
    let expected_measurement = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        &manifest_digest,
    );

    let content = build_package_toml(
        "",
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Web application"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        Some(&manifest),
        Some(&artifact),
        Some(&manifest_digest),
        None,
        None,
    )
    .unwrap();

    let rendered: toml::Value = toml::from_str(&content).unwrap();
    let platform = rendered
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.get("x86_64-linux"))
        .unwrap();
    let features = platform
        .get("requires-features")
        .and_then(toml::Value::as_array)
        .map(|features| {
            features
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert!(features.contains(&FEATURE_ATTESTATION_V1));
    assert_eq!(
        platform.get("root_digest").and_then(toml::Value::as_str),
        Some(root_hash)
    );
    assert_eq!(
        platform.get("root_hash").and_then(toml::Value::as_str),
        Some(root_hash)
    );
    assert_eq!(
        platform.get("root_hash_sig").and_then(toml::Value::as_str),
        Some("root.roothash.p7s")
    );
    let expected_provenance =
        publish_provenance_ref("webapp", "x86_64-linux", &expected_measurement).unwrap();
    assert_eq!(
        platform.get("provenance").and_then(toml::Value::as_str),
        Some(expected_provenance.as_str())
    );
    assert_eq!(
        platform.get("measurement").and_then(toml::Value::as_str),
        Some(expected_measurement.as_str())
    );

    let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
        .unwrap()
        .unwrap();
    assert_eq!(parsed.attestation.root_digest.as_deref(), Some(root_hash));
    assert_eq!(parsed.attestation.root_hash.as_deref(), Some(root_hash));
    assert_eq!(
        parsed.attestation.root_hash_sig.as_deref(),
        Some("root.roothash.p7s")
    );
    assert_eq!(
        parsed.attestation.provenance.as_deref(),
        Some(expected_provenance.as_str())
    );
    assert_eq!(
        parsed.attestation.measurement.as_deref(),
        Some(expected_measurement.as_str())
    );
}

#[test]
fn build_package_toml_update_existing() {
    let existing = r#"[package]
name = "curl"
description = "URL transfer tool"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/old-curl-8.5.0"
nar_hash = "sha256:old"
nar_size = 100
closure_size = 500
source_drv = ""
source_nar_hash = ""
references = []
"#;
    let info = StorePathInfo {
        path: "/nix/store/new-curl-8.5.0".into(),
        nar_hash: "sha256:new".into(),
        nar_size: 200,
        references: vec![],
        closure_size: 600,
    };
    let content = build_package_toml(
        existing,
        "curl",
        "8.5.0",
        "aarch64-linux",
        &info,
        Some("URL transfer tool"),
        None,
        Some("MIT"),
        Some("aos-team"),
        false,
        None,
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    // Should contain both platforms.
    assert!(content.contains("x86_64-linux"));
    assert!(content.contains("aarch64-linux"));
    assert!(content.contains("/nix/store/new-curl-8.5.0"));
    // The pre-existing platform's legacy fields survive untouched; the
    // new platform entry carries no nar_hash (RFC-0005).
    assert!(content.contains("sha256:old"));
    assert!(!content.contains("sha256:new"));
}

#[test]
fn build_package_toml_with_sysroot() {
    let image_fixture = TempDir::new().unwrap();
    let info = StorePathInfo {
        path: "/nix/store/abc123-server-2026.04".into(),
        nar_hash: "sha256:aabb".into(),
        nar_size: 12345678,
        references: vec!["ref1".into()],
        closure_size: 52428800,
    };
    let img_info = write_direct_image_output(
        image_fixture.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
    let image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();
    let content = build_package_toml(
        "",
        "server",
        "2026.04",
        "x86_64-linux",
        &info,
        Some("AOS server"),
        None,
        Some("MIT"),
        Some("aos-team"),
        true,
        Some("2026.03"),
        &[image],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert!(content.contains("sysroot = true"));
    assert!(content.contains("previous = \"2026.03\""));
    assert!(content.contains("format = \"raw\""));
    assert!(content.contains("sha256:1111111111111111111111111111111111111111111111111111"));
    assert!(content.contains("sha256:2222222222222222222222222222222222222222222222222222"));
    let parsed = crate::registry::parse::parse_package_file(&content).unwrap();
    let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
    assert_eq!(image.delivery.schema_version, 2);
    assert!(image.delivery.object_key.is_empty());
}

#[test]
fn build_package_toml_keeps_disk_image_verity_sidecars_out_of_catalog() {
    let image_fixture = TempDir::new().unwrap();
    let info = StorePathInfo {
        path: "/nix/store/abc123-server-2026.04".into(),
        nar_hash: "sha256:aabb".into(),
        nar_size: 12345678,
        references: vec!["ref1".into()],
        closure_size: 52428800,
    };
    let img_info = write_direct_image_output(
        image_fixture.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    let image_root = Path::new(&img_info.path);
    fs::write(image_root.join("root.img"), b"root").unwrap();
    fs::write(image_root.join("root.verity"), b"verity").unwrap();
    fs::write(image_root.join("root.roothash"), "a".repeat(64)).unwrap();
    fs::write(image_root.join("root.roothash.p7s"), b"signature").unwrap();
    rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
    let image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();

    let content = build_package_toml(
        "",
        "server",
        "2026.04",
        "x86_64-linux",
        &info,
        Some("AOS server"),
        None,
        Some("MIT"),
        Some("aos-team"),
        true,
        None,
        &[image],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let parsed = crate::registry::parse::parse_package_file(&content).unwrap();
    let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
    assert_eq!(image.format, "raw");
    assert!(image.root_image.is_none());
    assert!(image.root_verity.is_none());
    assert!(image.root_hash.is_none());
    assert!(image.root_hash_sig.is_none());
}

#[test]
fn build_package_toml_catalogs_verity_for_raw_recovery_image() {
    let image_fixture = TempDir::new().unwrap();
    let info = StorePathInfo {
        path: "/nix/store/abc123-server-2026.04".into(),
        nar_hash: "sha256:aabb".into(),
        nar_size: 12345678,
        references: vec!["ref1".into()],
        closure_size: 52428800,
    };
    let img_info = write_direct_image_output(
        image_fixture.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    let image_root = Path::new(&img_info.path);
    fs::write(image_root.join("root.img"), b"root").unwrap();
    fs::write(image_root.join("root.verity"), b"verity").unwrap();
    fs::write(image_root.join("root.roothash"), "a".repeat(64)).unwrap();
    fs::write(image_root.join("root.roothash.p7s"), b"signature").unwrap();
    rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
    let mut image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();
    image.sb.recovery_ukis.push(RecoveryUkiEntry {
        copy: UkiSlot::A,
        path: "recovery-a.efi".into(),
        entry_path: "recovery-a.conf".into(),
        byte_size: 1,
        sha256: "b".repeat(64),
        release: "2026.04".into(),
        recovery_abi: 1,
        sb_signer_cert_sha256: "c".repeat(64),
        sbat: vec![SbatEntry {
            component: "aos".into(),
            generation: 1,
        }],
    });

    let content = build_package_toml(
        "",
        "server",
        "2026.04",
        "x86_64-linux",
        &info,
        Some("AOS server"),
        None,
        Some("MIT"),
        Some("aos-team"),
        true,
        None,
        &[image],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(content.contains("root_image = \"root.img\""));
    assert!(content.contains("root_verity = \"root.verity\""));
    assert!(content.contains(&format!("root_hash = \"sha256:{}\"", "a".repeat(64))));
    assert!(content.contains("root_hash_sig = \"root.roothash.p7s\""));
}

#[test]
fn build_package_toml_escapes_maintainer_metadata() {
    let image_fixture = TempDir::new().unwrap();
    let info = StorePathInfo {
        path: "/nix/store/abc123-tool-1.0.0".into(),
        nar_hash: "sha256:aabb".into(),
        nar_size: 42,
        references: vec!["ref\"one".into()],
        closure_size: 84,
    };
    let img_info = write_direct_image_output(
        image_fixture.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    rewrite_test_image_parent(&img_info, "1.0.0", "x86_64-linux");
    let image = inspect_test_image("raw", img_info, "1.0.0", "x86_64-linux").unwrap();

    let content = build_package_toml(
        "",
        "tool",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some("Tool with \"quoted\" metadata\nand a second line"),
        Some("https://example.invalid/tool?feature=\"quotes\""),
        Some("MIT OR Apache-2.0"),
        Some("AOS Team <aos@example.invalid>"),
        false,
        Some("0.9.0+build\"meta"),
        &[image],
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let rendered: toml::Value = toml::from_str(&content).unwrap();
    assert_eq!(
        rendered
            .get("package")
            .and_then(|package| package.get("description"))
            .and_then(|description| description.as_str()),
        Some("Tool with \"quoted\" metadata\nand a second line")
    );
    assert_eq!(
        rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("previous"))
            .and_then(|previous| previous.as_str()),
        Some("0.9.0+build\"meta")
    );
    assert_eq!(
        rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("x86_64-linux"))
            .and_then(|platform| platform.get("images"))
            .and_then(|images| images.as_array())
            .and_then(|images| images.first())
            .and_then(|image| image.get("format"))
            .and_then(|format| format.as_str()),
        Some("raw")
    );
}
