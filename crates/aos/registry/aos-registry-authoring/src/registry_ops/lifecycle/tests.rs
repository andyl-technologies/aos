//! Tests for authoring-clone discovery, protection against data loss, and registry creation.

use super::{
    InitialRoster, authoring_clone_precious, extra_roster_key_ids, initial_keys_roster,
    local_registries,
};
use crate::registry_ops::require_active_registry_key;
use crate::registry_ops::test_support::init_authoring_clone;
use crate::testutil;
use aos_registry_client::registry::keys;
use std::fs;
use tempfile::TempDir;

const PRIMARY_KEY: &str = "aos-core:Ed25519:YWJjZA==";
const PROVENANCE_KEY: &str = "aos-core:Ed25519:ZWZnaA==";

/// Builds an `apr create` roster request from command-line style values.
fn roster_request<'a>(
    trust_key: Option<&'a str>,
    trust_key_id: Option<&'a str>,
    roster_keys: &'a [String],
) -> InitialRoster<'a> {
    InitialRoster {
        trust_key,
        trust_key_id,
        roster_keys,
    }
}

#[test]
fn initial_keys_roster_defaults_to_empty_schema_one_roster() {
    let roster = initial_keys_roster("aos-core", &InitialRoster::default()).unwrap();
    assert_eq!(roster.schema, keys::KEYS_TOML_SCHEMA);
    assert!(roster.active.is_empty());
    assert!(roster.revoked.is_empty());
}

#[test]
fn initial_keys_roster_accepts_matching_registry_key() {
    let request = roster_request(Some(PRIMARY_KEY), Some("2026a"), &[]);
    let roster = initial_keys_roster("aos-core", &request).unwrap();
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.active[0].id, "2026a");
    assert_eq!(roster.active[0].key, PRIMARY_KEY);
}

#[test]
fn initial_keys_roster_defaults_key_id_when_key_is_supplied() {
    let request = roster_request(Some(PRIMARY_KEY), None, &[]);
    let roster = initial_keys_roster("aos-core", &request).unwrap();
    assert_eq!(roster.active[0].id, "initial");
}

#[test]
fn initial_keys_roster_rejects_key_id_without_key() {
    let request = roster_request(None, Some("2026a"), &[]);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(format!("{err:#}").contains("--trust-key-id requires --trust-key"));
}

#[test]
fn initial_keys_roster_rejects_invalid_key_id() {
    let request = roster_request(Some(PRIMARY_KEY), Some("bad/id"), &[]);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(format!("{err:#}").contains("key id"));
}

#[test]
fn initial_keys_roster_rejects_foreign_registry_key() {
    let request = roster_request(Some("other:Ed25519:YWJjZA=="), Some("2026a"), &[]);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(format!("{err:#}").contains("expected 'aos-core'"));
}

#[test]
fn initial_keys_roster_appends_roster_keys_after_the_primary_key() {
    let roster_keys = vec![
        format!("provenance={PROVENANCE_KEY}"),
        "backup=aos-core:Ed25519:aGlqaw==".to_string(),
    ];
    let request = roster_request(Some(PRIMARY_KEY), Some("signer"), &roster_keys);

    let roster = initial_keys_roster("aos-core", &request).unwrap();

    let ids: Vec<&str> = roster
        .active
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    assert_eq!(ids, ["signer", "provenance", "backup"]);
    assert_eq!(roster.active[1].key, PROVENANCE_KEY);
    assert_eq!(extra_roster_key_ids(&roster), ["provenance", "backup"]);
}

#[test]
fn initial_roster_keys_are_active_for_provenance_signing() {
    let tmp = TempDir::new().unwrap();
    let roster_keys = vec![format!("provenance={PROVENANCE_KEY}")];
    let request = roster_request(Some(PRIMARY_KEY), Some("signer"), &roster_keys);
    let roster = initial_keys_roster("aos-core", &request).unwrap();

    keys::write_keys_toml(tmp.path(), &roster).unwrap();

    let loaded = keys::load_keys_toml(tmp.path()).unwrap().unwrap();
    assert_eq!(loaded, roster);
    require_active_registry_key(tmp.path(), "signer", PRIMARY_KEY).unwrap();
    require_active_registry_key(tmp.path(), "provenance", PROVENANCE_KEY).unwrap();
}

#[test]
fn initial_keys_roster_rejects_roster_key_without_trust_key() {
    let roster_keys = vec![format!("provenance={PROVENANCE_KEY}")];
    let request = roster_request(None, None, &roster_keys);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(format!("{err:#}").contains("--roster-key requires --trust-key"));
}

#[test]
fn initial_keys_roster_rejects_roster_key_reusing_the_primary_id() {
    let roster_keys = vec![format!("initial={PROVENANCE_KEY}")];
    let request = roster_request(Some(PRIMARY_KEY), None, &roster_keys);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(
        format!("{err:#}").contains("reuses roster key id 'initial'"),
        "{err:#}"
    );
}

#[test]
fn initial_keys_roster_rejects_repeated_roster_key_ids() {
    let roster_keys = vec![
        format!("provenance={PROVENANCE_KEY}"),
        "provenance=aos-core:Ed25519:aGlqaw==".to_string(),
    ];
    let request = roster_request(Some(PRIMARY_KEY), None, &roster_keys);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(
        format!("{err:#}").contains("reuses roster key id 'provenance'"),
        "{err:#}"
    );
}

#[test]
fn initial_keys_roster_rejects_roster_key_repeating_a_public_key() {
    let roster_keys = vec![format!("provenance={PRIMARY_KEY}")];
    let request = roster_request(Some(PRIMARY_KEY), None, &roster_keys);
    let err = initial_keys_roster("aos-core", &request).unwrap_err();
    assert!(
        format!("{err:#}").contains("repeats the public key of roster key 'initial'"),
        "{err:#}"
    );
}

#[test]
fn initial_keys_roster_rejects_malformed_roster_keys() {
    let cases = [
        (
            "missing separator",
            PROVENANCE_KEY.to_string(),
            "must have the form",
        ),
        (
            "empty id",
            format!("={PROVENANCE_KEY}"),
            "key id cannot be empty",
        ),
        (
            "invalid id",
            format!("bad/id={PROVENANCE_KEY}"),
            "must contain only",
        ),
        (
            "not a trust line",
            "provenance=not-a-key".to_string(),
            "malformed signing key",
        ),
        (
            "unsupported algorithm",
            "provenance=aos-core:Rsa:ZWZnaA==".to_string(),
            "unsupported signing algorithm",
        ),
        (
            "foreign registry",
            "provenance=other:Ed25519:ZWZnaA==".to_string(),
            "belongs to registry 'other', expected 'aos-core'",
        ),
    ];

    for (case, argument, expected) in cases {
        let roster_keys = vec![argument];
        let request = roster_request(Some(PRIMARY_KEY), None, &roster_keys);
        let err = initial_keys_roster("aos-core", &request).unwrap_err();
        assert!(
            format!("{err:#}").contains(expected),
            "{case}: expected {expected:?} in {err:#}"
        );
    }
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
