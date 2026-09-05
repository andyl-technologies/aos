//! Tests for trust pins, committed signing-key rosters, and retirement re-signing.

use super::{
    execute_retirement_resign, hash_tag_object, plan_retirement_resign, retire_roster_key,
};
use crate::registry::channel;
use crate::registry::keys::{KeysToml, RosterKey};
use crate::registry_ops::channels::{channel_init_dir, read_channel_partition_map};
use crate::registry_ops::git::git;
use crate::registry_ops::tags::sign_tag;
use crate::registry_ops::test_support::write_seeded_signing_key;
use crate::security::verify_tag_signature;
use aos_core::output::Printer;
use std::fs;
use tempfile::TempDir;

#[test]
fn retire_roster_key_preserves_provenance_key_cutoff() {
    let mut roster = KeysToml {
        active: vec![
            RosterKey {
                id: "old".to_string(),
                key: "aos-core:Ed25519:YWJjZA==".to_string(),
            },
            RosterKey {
                id: "new".to_string(),
                key: "aos-core:Ed25519:ZWZnaA==".to_string(),
            },
        ],
        ..KeysToml::default()
    };

    let vouching_id =
        retire_roster_key(&mut roster, "old", Some("planned"), &None, 4).expect("retire key");

    assert_eq!(vouching_id, "new");
    assert!(roster.active.iter().all(|entry| entry.id != "old"));
    assert_eq!(roster.revoked.len(), 1);
    assert_eq!(roster.revoked[0].id, "old");
    assert_eq!(
        roster.revoked[0].key.as_deref(),
        Some("aos-core:Ed25519:YWJjZA==")
    );
    assert_eq!(roster.revoked[0].provenance_before_sequence, Some(4));
}

#[test]
fn retirement_resign_rotates_release_and_partition_signatures() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=stable",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();

    // Maintainer A signs everything and then retires; B survives.
    let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [9u8; 32], "key_a");
    let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [10u8; 32], "key_b");
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let version = semver::Version::new(1, 0, 0);
    let key_a_path = key_a.private_key.to_str().unwrap();
    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        Some("release 1.0.0"),
        key_a_path,
        false,
    )
    .unwrap();
    let printer = Printer::new(0, true, false);
    channel_init_dir(&repo, "prod", &version, key_a_path, &printer).unwrap();

    // Nothing is affected while A is still a survivor.
    let survivors_both = vec![key_a.trusted_key.clone(), key_b.trusted_key.clone()];
    let plan = plan_retirement_resign(&repo, &survivors_both).unwrap();
    assert!(plan.is_empty());

    // Retiring A: the release tag and every partition need re-signing.
    let survivors = vec![key_b.trusted_key.clone()];
    let plan = plan_retirement_resign(&repo, &survivors).unwrap();
    assert_eq!(plan.affected_releases, vec![version.clone()]);
    assert_eq!(plan.affected_partitions.len(), 256);

    execute_retirement_resign(&repo, &plan, key_b.private_key.to_str().unwrap(), &printer).unwrap();

    // The release tag now verifies only against the survivor.
    assert!(
        verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_b.trusted_key)).unwrap()
    );
    assert!(
        !verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_a.trusted_key)).unwrap()
    );

    // Partition payloads were regenerated against the new tag object
    // and verify against the survivor.
    let payload = fs::read(repo.join(".git/channels/prod/00")).unwrap();
    let oid = hash_tag_object(&repo, &payload).unwrap();
    assert!(verify_tag_signature(&repo, &oid, std::slice::from_ref(&key_b.trusted_key)).unwrap());
    let map = read_channel_partition_map(&repo, "prod").unwrap();
    assert_eq!(channel::compute_frontier(&map), Some(version));

    // Re-planning against the survivor finds nothing left to re-sign.
    let plan = plan_retirement_resign(&repo, &survivors).unwrap();
    assert!(plan.is_empty());
}

#[test]
fn retirement_resign_includes_release_tags_without_channels() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=stable",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();

    let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [11u8; 32], "key_a");
    let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [12u8; 32], "key_b");
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let version = semver::Version::new(1, 0, 0);
    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        Some("release 1.0.0"),
        key_a.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();

    let survivors = vec![key_b.trusted_key.clone()];
    let plan = plan_retirement_resign(&repo, &survivors).unwrap();

    assert_eq!(plan.affected_releases, vec![version]);
    assert!(plan.affected_partitions.is_empty());
}
