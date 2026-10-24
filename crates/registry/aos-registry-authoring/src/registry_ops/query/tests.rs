//! Tests for package listing, version selection, removal, and closure integrity verification.

use super::{
    latest_version_string, matching_package_versions, package_toml_with_versions,
    selected_package_versions,
};

#[test]
fn selected_package_versions_filters_exact_version() {
    let toml_val: toml::Value = toml::from_str(
        r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-2.0.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []
"#,
    )
    .unwrap();

    let selected = selected_package_versions(&toml_val, Some("1.0.0")).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0]
            .get("version")
            .and_then(|version| version.as_str()),
        Some("1.0.0")
    );
    assert!(selected_package_versions(&toml_val, Some("9.9.9")).is_err());

    let raw = package_toml_with_versions(&toml_val, &selected).unwrap();
    let rendered = toml::to_string_pretty(&raw).unwrap();
    assert!(rendered.contains("1.0.0"));
    assert!(!rendered.contains("2.0.0"));
}

#[test]
fn latest_version_string_uses_semver_and_platform_filter() {
    let toml_val: toml::Value = toml::from_str(
        r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.9.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.9.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "1.10.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-1.10.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "3.0.0"

[versions.platforms.aarch64-linux]
store_path = "/nix/store/ccc333-tool-3.0.0"
nar_hash = "sha256:v3"
nar_size = 3
closure_size = 3
source_drv = ""
source_nar_hash = ""
references = []
"#,
    )
    .unwrap();

    assert_eq!(
        latest_version_string(&matching_package_versions(&toml_val, Some("x86_64-linux"))),
        Some("1.10.0".to_string())
    );
    assert_eq!(
        latest_version_string(&matching_package_versions(&toml_val, Some("aarch64-linux"))),
        Some("3.0.0".to_string())
    );
    assert!(matching_package_versions(&toml_val, Some("riscv64-linux")).is_empty());
}
