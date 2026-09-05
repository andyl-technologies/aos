//! Tests for authoring-clone discovery, protection against data loss, and registry creation.

use super::{authoring_clone_precious, initial_keys_roster, local_registries};
use crate::registry::keys;
use crate::registry_ops::test_support::init_authoring_clone;
use crate::testutil;
use std::fs;
use tempfile::TempDir;

#[test]
fn initial_keys_roster_defaults_to_empty_schema_one_roster() {
    let roster = initial_keys_roster("aos-core", None, None).unwrap();
    assert_eq!(roster.schema, keys::KEYS_TOML_SCHEMA);
    assert!(roster.active.is_empty());
    assert!(roster.revoked.is_empty());
}

#[test]
fn initial_keys_roster_accepts_matching_registry_key() {
    let roster =
        initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), Some("2026a")).unwrap();
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.active[0].id, "2026a");
    assert_eq!(roster.active[0].key, "aos-core:Ed25519:YWJjZA==");
}

#[test]
fn initial_keys_roster_defaults_key_id_when_key_is_supplied() {
    let roster = initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), None).unwrap();
    assert_eq!(roster.active[0].id, "initial");
}

#[test]
fn initial_keys_roster_rejects_key_id_without_key() {
    let err = initial_keys_roster("aos-core", None, Some("2026a")).unwrap_err();
    assert!(format!("{err:#}").contains("--trust-key-id requires --trust-key"));
}

#[test]
fn initial_keys_roster_rejects_invalid_key_id() {
    let err = initial_keys_roster(
        "aos-core",
        Some("aos-core:Ed25519:YWJjZA=="),
        Some("bad/id"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("key id"));
}

#[test]
fn initial_keys_roster_rejects_foreign_registry_key() {
    let err =
        initial_keys_roster("aos-core", Some("other:Ed25519:YWJjZA=="), Some("2026a")).unwrap_err();
    assert!(format!("{err:#}").contains("expected 'aos-core'"));
}

#[test]
fn local_registries_skips_configured_names() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("configured-reg")).unwrap();
    fs::create_dir_all(tmp.path().join("authored-reg/packages/t")).unwrap();
    fs::write(
        tmp.path().join("authored-reg/packages/t/tool-1.0.0.toml"),
        "",
    )
    .unwrap();

    let local = local_registries(tmp.path(), &["configured-reg"]);
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].name, "authored-reg");
    assert_eq!(local[0].packages, 1);
    assert_eq!(local[0].origin, None);
}

#[test]
fn local_registries_reports_origin() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("authored-reg");
    init_authoring_clone(&dir);
    testutil::git(
        &dir,
        &["remote", "add", "origin", "https://cdn.example.com/reg"],
    );

    let local = local_registries(tmp.path(), &[]);
    assert_eq!(local.len(), 1);
    assert_eq!(
        local[0].origin.as_deref(),
        Some("https://cdn.example.com/reg")
    );
}

#[test]
fn local_registries_missing_dir_is_empty() {
    let tmp = TempDir::new().unwrap();
    assert!(local_registries(&tmp.path().join("absent"), &[]).is_empty());
}

#[test]
fn authoring_clone_precious_ignores_plain_dirs() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("consumer-reg");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();

    assert!(authoring_clone_precious(&dir).unwrap().is_none());
    assert!(
        authoring_clone_precious(&tmp.path().join("absent"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn authoring_clone_precious_without_remote() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("authored-reg");
    init_authoring_clone(&dir);

    let reason = authoring_clone_precious(&dir).unwrap();
    assert!(
        reason.as_deref().is_some_and(|r| r.contains("no remote")),
        "got: {reason:?}"
    );
}

#[test]
fn authoring_clone_precious_uncommitted_changes() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("authored-reg");
    init_authoring_clone(&dir);
    fs::write(dir.join("registry.toml"), "[registry]\nname = \"x\"\n").unwrap();

    let reason = authoring_clone_precious(&dir).unwrap();
    assert_eq!(reason.as_deref(), Some("uncommitted changes"));
}

#[test]
fn authoring_clone_precious_unpushed_and_pushed() {
    let tmp = TempDir::new().unwrap();
    let origin = tmp.path().join("origin.git");
    fs::create_dir_all(&origin).unwrap();
    testutil::git(&origin, &["init", "--bare"]);

    let dir = tmp.path().join("authored-reg");
    init_authoring_clone(&dir);
    testutil::git(&dir, &["remote", "add", "origin", origin.to_str().unwrap()]);

    let reason = authoring_clone_precious(&dir).unwrap();
    assert!(
        reason
            .as_deref()
            .is_some_and(|r| r.contains("not pushed to any remote")),
        "got: {reason:?}"
    );

    let branch = testutil::git(&dir, &["branch", "--show-current"]);
    testutil::git(&dir, &["push", "origin", &branch]);
    assert!(authoring_clone_precious(&dir).unwrap().is_none());
}
