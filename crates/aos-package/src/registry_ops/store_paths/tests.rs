//! Tests for nix store introspection, release-policy checks, and realisation graph publication.

use super::{
    RELEASE_POLICY_RELATIVE_PATH, extract_hash, first_letter, parse_store_path,
    resolve_publish_platform, store_dir_from_store_path,
    validate_store_path_release_policy_in_closure,
};
use crate::platform::native_platform;
use crate::registry_ops::test_support::{release_policy_info, write_internal_release_policy};
use std::fs;
use tempfile::TempDir;

#[test]
fn publish_platform_uses_cross_target_marker() {
    let output = TempDir::new().unwrap();
    let support = output.path().join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "aarch64-darwin\n").unwrap();

    assert_eq!(
        resolve_publish_platform(output.path().to_str().unwrap(), None).unwrap(),
        "aarch64-darwin"
    );
}

#[test]
fn publish_platform_accepts_matching_explicit_target() {
    let output = TempDir::new().unwrap();
    let support = output.path().join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "x86_64-darwin\n").unwrap();

    assert_eq!(
        resolve_publish_platform(output.path().to_str().unwrap(), Some("x86_64-darwin")).unwrap(),
        "x86_64-darwin"
    );
}

#[test]
fn publish_platform_rejects_mismatched_explicit_target() {
    let output = TempDir::new().unwrap();
    let support = output.path().join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "aarch64-darwin\n").unwrap();

    let error = resolve_publish_platform(output.path().to_str().unwrap(), Some("x86_64-linux"))
        .unwrap_err();
    assert!(format!("{error:#}").contains("disagrees with target platform marker"));
}

#[test]
fn publish_platform_preserves_native_fallback_for_legacy_outputs() {
    let output = TempDir::new().unwrap();

    assert_eq!(
        resolve_publish_platform(output.path().to_str().unwrap(), None).unwrap(),
        native_platform()
    );
}

#[test]
fn raw_internal_component_publication_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let qemu = tmp
        .path()
        .join("0000000000000000000000000000000a-qemu-crucible");
    write_internal_release_policy(&qemu, "build-1");

    let error = validate_store_path_release_policy_in_closure(
        &release_policy_info(&qemu, vec![]),
        &[qemu.to_string_lossy().into_owned()],
    )
    .unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("is not an aggregate release root"));
}

#[test]
fn unmarked_wrapper_around_internal_component_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let wrapper = tmp.path().join("0000000000000000000000000000000a-wrapper");
    let qemu = tmp.path().join("0000000000000000000000000000000b-qemu");
    fs::create_dir_all(&wrapper).unwrap();
    write_internal_release_policy(&qemu, "build-1");
    let error = validate_store_path_release_policy_in_closure(
        &release_policy_info(
            &wrapper,
            vec![extract_hash(qemu.to_str().unwrap()).to_owned()],
        ),
        &[
            wrapper.to_string_lossy().into_owned(),
            qemu.to_string_lossy().into_owned(),
        ],
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("has no aggregate release policy"));
}

#[test]
fn plugin_shaped_wrapper_around_internal_component_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let plugin = tmp
        .path()
        .join("0000000000000000000000000000000a-crucible-qemu-plugin");
    let qemu = tmp.path().join("0000000000000000000000000000000b-qemu");
    fs::create_dir_all(&plugin).unwrap();
    write_internal_release_policy(&qemu, "build-1");
    let error = validate_store_path_release_policy_in_closure(
        &release_policy_info(
            &plugin,
            vec![extract_hash(qemu.to_str().unwrap()).to_owned()],
        ),
        &[
            plugin.to_string_lossy().into_owned(),
            qemu.to_string_lossy().into_owned(),
        ],
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("has no aggregate release policy"));
}

#[test]
fn complete_aggregate_publication_retains_matching_source() {
    let tmp = TempDir::new().unwrap();
    let suite = tmp.path().join("0000000000000000000000000000000a-crucible");
    let qemu = tmp
        .path()
        .join("0000000000000000000000000000000b-qemu-crucible");
    let source = tmp
        .path()
        .join("0000000000000000000000000000000c-qemu-crucible-source");
    fs::create_dir_all(suite.join("nix-support")).unwrap();
    write_internal_release_policy(&qemu, "build-1");
    fs::create_dir_all(source.join("nix-support")).unwrap();
    fs::write(
        source.join("nix-support/qemu-crucible-source-build-info"),
        "qemu_build_id=build-1\n",
    )
    .unwrap();
    fs::write(
        suite.join(RELEASE_POLICY_RELATIVE_PATH),
        format!(
            "policy_version=1\nartifact_role=aggregate-release-root\nstandalone_release=true\npair_count=1\npair_1_component_path={}\npair_1_corresponding_source_path={}\npair_1_identity=build-1\n",
            qemu.display(),
            source.display()
        ),
    )
    .unwrap();
    let paired = release_policy_info(
        &suite,
        vec![
            extract_hash(qemu.to_str().unwrap()).to_string(),
            extract_hash(source.to_str().unwrap()).to_string(),
        ],
    );
    validate_store_path_release_policy_in_closure(
        &paired,
        &[
            suite.to_string_lossy().into_owned(),
            qemu.to_string_lossy().into_owned(),
            source.to_string_lossy().into_owned(),
        ],
    )
    .unwrap();
}

#[test]
fn generic_unmarked_qemu_publication_remains_allowed() {
    let tmp = TempDir::new().unwrap();
    let qemu = tmp.path().join("0000000000000000000000000000000a-qemu");
    fs::create_dir_all(&qemu).unwrap();
    validate_store_path_release_policy_in_closure(
        &release_policy_info(&qemu, vec![]),
        &[qemu.to_string_lossy().into_owned()],
    )
    .unwrap();
}

#[test]
fn parse_store_path_standard() {
    let (name, version) =
        parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-curl-8.5.0");
    assert_eq!(name, "curl");
    assert_eq!(version, "8.5.0");
}

#[test]
fn parse_store_path_multi_dash_name() {
    let (name, version) =
        parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-my-cool-package-1.2.3");
    assert_eq!(name, "my-cool-package");
    assert_eq!(version, "1.2.3");
}

#[test]
fn parse_store_path_no_version() {
    let (name, version) = parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-just-name");
    assert_eq!(name, "just-name");
    assert_eq!(version, "0.0.0");
}

#[test]
fn first_letter_basic() {
    assert_eq!(first_letter("curl"), "c");
    assert_eq!(first_letter("Zlib"), "z");
}

#[test]
fn store_dir_from_store_path_accepts_alternate_stores() {
    assert_eq!(
        store_dir_from_store_path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-curl-8.5.0"),
        Some("/nix/store"),
    );
    assert_eq!(
        store_dir_from_store_path(
            "/build/aos-root/store/0123456789abcdfghijklmnpqrsvwxyz-curl-8.5.0.drv",
        ),
        Some("/build/aos-root/store"),
    );
    assert_eq!(store_dir_from_store_path("unknown-deriver"), None);
    assert_eq!(
        store_dir_from_store_path("/nix/store/not-a-store-path"),
        None
    );
}
