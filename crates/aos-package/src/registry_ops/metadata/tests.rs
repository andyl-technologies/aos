//! Tests for package catalog TOML construction and platform metadata recording.

use super::{build_package_toml, record_named_output};
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    inspect_test_image, rewrite_test_image_parent, write_direct_image_output,
};
use crate::types::{FEATURE_IMAGE_ARTIFACT_CONTRACT_V1, PACKAGE_META_FORMAT};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn sysroot_publication_emits_structural_native_rollout_gate() {
    let info = StorePathInfo {
        path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-system".to_string(),
        nar_hash: format!("sha256:{}", "1".repeat(64)),
        nar_size: 1024,
        references: Vec::new(),
        closure_size: 1024,
    };
    let content = build_package_toml(
        "",
        "aos",
        "1",
        "x86_64-linux",
        &info,
        Some("AOS system"),
        None,
        Some("Apache-2.0"),
        Some("Andyl, Inc."),
        true,
        None,
        &[],
        None,
    )
    .expect("build sysroot metadata");
    let parsed = crate::registry::parse::parse_package_file(&content)
        .expect("parse published sysroot metadata");
    let platform = &parsed.versions[0].platforms["x86_64-linux"];

    assert!(platform.references.is_gate());
    for features in [
        platform.requires_features.as_slice(),
        platform.references.requires_features(),
    ] {
        assert_eq!(features, [FEATURE_IMAGE_ARTIFACT_CONTRACT_V1]);
    }
    assert_eq!(platform.min_format, Some(PACKAGE_META_FORMAT));
    assert_eq!(platform.references.min_format(), Some(PACKAGE_META_FORMAT));
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
fn named_output_extends_the_exact_primary_platform() {
    let existing = r#"
[package]
name = "curl"
description = "URL transfer tool"
license = "curl"
maintainer = "aos"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/abc123-curl-8.5.0"
closure_size = 1
source_drv = ""
source_nar_hash = ""
"#;
    let content = record_named_output(
        existing,
        "curl",
        "8.5.0",
        "x86_64-linux",
        "dev",
        "/nix/store/def456-curl-8.5.0-dev",
    )
    .expect("record named output");
    let package: aos_registry_surface::manifest::PackageToml =
        toml::from_str(&content).expect("parse extended package");
    let platform = package.versions[0]
        .platforms
        .get("x86_64-linux")
        .expect("platform entry");

    assert_eq!(platform.store_path, "/nix/store/abc123-curl-8.5.0");
    assert_eq!(
        platform
            .named_outputs
            .get("dev")
            .map(|metadata| metadata.store_path.as_str()),
        Some("/nix/store/def456-curl-8.5.0-dev")
    );

    let error = record_named_output(
        &content,
        "curl",
        "8.5.0",
        "x86_64-linux",
        "dev",
        "/nix/store/ghi789-curl-8.5.0-tools",
    )
    .expect_err("conflicting named output");
    assert!(format!("{error:#}").contains("already bound"));
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
    )
    .unwrap();
    assert!(content.contains("source_drv = \"/nix/store/drv123-curl-8.5.0.drv\""));
    assert!(content.contains("source_nar_hash = \"sha256:source\""));
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
fn build_package_toml_keeps_provider_contract_fields_out_of_catalog() {
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
    fs::write(image_root.join("provider-artifact"), b"opaque").unwrap();
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
    )
    .unwrap();

    let parsed = crate::registry::parse::parse_package_file(&content).unwrap();
    let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
    assert_eq!(image.format, "raw");
    assert_eq!(
        image.delivery.artifact_contract.schema,
        "aos.test-boot-artifacts/v1"
    );
    for provider_field in ["providerContract", "opaqueEvidence", "provider-owned"] {
        assert!(!content.contains(provider_field));
    }
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
