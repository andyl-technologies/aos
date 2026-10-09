//! Tests for trust pins, committed signing-key rosters, and retirement re-signing.

use super::{
    RetirementOptions, execute_retirement_resign, plan_retirement_resign, retire_committed_key,
    retire_roster_key, verify_partition_signature,
};
use aos_registry_client::config::ApmConfig;
use aos_registry_client::registry::channel;
use aos_registry_client::registry::keys::{self, KeysToml, RosterKey};
use crate::registry_ops::channels::{channel_init_dir, read_channel_partition_map};
use crate::registry_ops::git::git;
use crate::registry_ops::tags::sign_tag;
use crate::registry_ops::test_support::{
    TestSigningFixture, test_config_with_signing_key, write_seeded_signing_key,
};
use aos_registry_client::security::verify_tag_signature;
use aos_cli_ui::output::Printer;
use std::fs;
use std::path::PathBuf;
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
fn retirement_resign_rejects_release_rewrite_before_partition_mutation() {
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

    // Retiring A would invalidate the immutable release and its partitions.
    let survivors = vec![key_b.trusted_key.clone()];
    let plan = plan_retirement_resign(&repo, &survivors).unwrap();
    assert_eq!(plan.affected_releases, vec![version.to_string()]);
    assert_eq!(plan.affected_partitions.len(), 256);

    let release_before = git(&repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();
    let partition_before = fs::read(repo.join(".git/channels/prod/00")).unwrap();
    let head_before = git(&repo, &["rev-parse", "HEAD"]).unwrap();
    let index_before = fs::read(repo.join(".git/index")).unwrap();

    let error =
        execute_retirement_resign(&repo, &plan, key_b.private_key.to_str().unwrap(), &printer)
            .unwrap_err();

    assert!(error.to_string().contains("immutable release tags (1.0.0)"));
    assert!(error.to_string().contains("--no-resign"));
    assert_eq!(
        git(&repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap(),
        release_before
    );
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]).unwrap(), head_before);
    assert_eq!(fs::read(repo.join(".git/index")).unwrap(), index_before);
    assert_eq!(
        fs::read(repo.join(".git/channels/prod/00")).unwrap(),
        partition_before
    );
    assert!(
        verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_a.trusted_key)).unwrap()
    );
    let map = read_channel_partition_map(&repo, "prod").unwrap();
    assert_eq!(channel::compute_frontier(&map), Some(version));
}

#[test]
fn retirement_resigns_partitions_without_changing_release_identity() {
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

    let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [19u8; 32], "key_a");
    let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [20u8; 32], "key_b");
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let version = semver::Version::new(1, 0, 0);
    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        None,
        key_b.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    let printer = Printer::new(0, true, false);
    channel_init_dir(
        &repo,
        "prod",
        &version,
        key_a.private_key.to_str().unwrap(),
        &printer,
    )
    .unwrap();
    let release_before = git(&repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();
    let survivors = vec![key_b.trusted_key.clone()];
    let plan = plan_retirement_resign(&repo, &survivors).unwrap();

    assert!(plan.affected_releases.is_empty());
    assert_eq!(plan.affected_partitions.len(), 256);

    execute_retirement_resign(&repo, &plan, key_b.private_key.to_str().unwrap(), &printer).unwrap();

    assert_eq!(
        git(&repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap(),
        release_before
    );
    let payload = fs::read(repo.join(".git/channels/prod/00")).unwrap();
    assert!(verify_partition_signature(&payload, &survivors).unwrap());
    assert!(!verify_partition_signature(&payload, &[key_a.trusted_key]).unwrap());
    let map = read_channel_partition_map(&repo, "prod").unwrap();
    assert_eq!(channel::compute_frontier(&map), Some(version));
    assert!(
        plan_retirement_resign(&repo, &survivors)
            .unwrap()
            .is_empty()
    );
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

    assert_eq!(plan.affected_releases, vec![version.to_string()]);
    assert!(plan.affected_partitions.is_empty());
}

struct RetirementFixture {
    _tmp: TempDir,
    repo: PathBuf,
    config: ApmConfig,
    old: TestSigningFixture,
    survivor: TestSigningFixture,
}

fn retirement_fixture() -> RetirementFixture {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
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

    let old = write_seeded_signing_key(tmp.path(), "aos-core", [31u8; 32], "old");
    let survivor = write_seeded_signing_key(tmp.path(), "aos-core", [32u8; 32], "survivor");
    keys::write_keys_toml(
        &repo,
        &KeysToml {
            active: vec![
                RosterKey {
                    id: "old".to_string(),
                    key: old.trusted_key.clone(),
                },
                RosterKey {
                    id: "survivor".to_string(),
                    key: survivor.trusted_key.clone(),
                },
            ],
            ..KeysToml::default()
        },
    )
    .unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init roster"]).unwrap();
    let config = test_config_with_signing_key("aos-core", "survivor", &survivor.private_key);

    RetirementFixture {
        _tmp: tmp,
        repo,
        config,
        old,
        survivor,
    }
}

fn retirement_options(no_resign: bool) -> RetirementOptions<'static> {
    RetirementOptions {
        id: "old",
        reason: Some("planned retirement"),
        vouched_by: &None,
        no_commit: false,
        signing_key: None,
        signing_key_id: None,
        no_resign,
    }
}

#[test]
fn consumed_release_aliases_block_retirement_using_their_actual_refs() {
    let fixture = retirement_fixture();
    // The canonical spelling remains trusted by the survivor. Only the
    // client-consumed aliases lose trust when the old signing key retires.
    sign_tag(
        &fixture.repo,
        "1.2.3",
        "HEAD",
        None,
        fixture.survivor.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    for name in ["v1.2.3", "2026.02", "v01.02.03"] {
        sign_tag(
            &fixture.repo,
            name,
            "HEAD",
            None,
            fixture.old.private_key.to_str().unwrap(),
            false,
        )
        .unwrap();
    }
    let roster_before = fs::read(fixture.repo.join("keys.toml")).unwrap();
    let index_before = fs::read(fixture.repo.join(".git/index")).unwrap();
    let head_before = git(&fixture.repo, &["rev-parse", "HEAD"]).unwrap();
    let tree_before = git(&fixture.repo, &["rev-parse", "HEAD^{tree}"]).unwrap();
    let config_before = fs::read(fixture.repo.join(".git/config")).unwrap();
    let names = ["v1.2.3", "2026.02", "v01.02.03"];
    let identities: Vec<_> = names
        .iter()
        .map(|name| git(&fixture.repo, &["rev-parse", &format!("refs/tags/{name}")]).unwrap())
        .collect();

    let plan =
        plan_retirement_resign(&fixture.repo, &[fixture.survivor.trusted_key.clone()]).unwrap();
    assert_eq!(
        plan.affected_releases,
        vec!["2026.02", "v01.02.03", "v1.2.3"]
    );
    let error = retire_committed_key(
        &fixture.config,
        &fixture.repo,
        "aos-core",
        retirement_options(false),
        &Printer::new(0, true, false),
    )
    .unwrap_err();

    assert!(error.to_string().contains("2026.02, v01.02.03, v1.2.3"));
    assert_eq!(
        fs::read(fixture.repo.join("keys.toml")).unwrap(),
        roster_before
    );
    assert_eq!(
        fs::read(fixture.repo.join(".git/index")).unwrap(),
        index_before
    );
    assert_eq!(
        fs::read(fixture.repo.join(".git/config")).unwrap(),
        config_before
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "HEAD"]).unwrap(),
        head_before
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "HEAD^{tree}"]).unwrap(),
        tree_before
    );
    for (name, identity) in names.iter().zip(identities) {
        assert_eq!(
            git(&fixture.repo, &["rev-parse", &format!("refs/tags/{name}")]).unwrap(),
            identity
        );
    }
}

#[test]
fn rejected_retirement_leaves_roster_tree_index_head_and_tag_unchanged() {
    let fixture = retirement_fixture();
    sign_tag(
        &fixture.repo,
        "1.0.0",
        "HEAD",
        None,
        fixture.old.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    let roster_before = fs::read(fixture.repo.join("keys.toml")).unwrap();
    let config_before = fs::read(fixture.repo.join(".git/config")).unwrap();
    let index_before = fs::read(fixture.repo.join(".git/index")).unwrap();
    let head_before = git(&fixture.repo, &["rev-parse", "HEAD"]).unwrap();
    let tree_before = git(&fixture.repo, &["rev-parse", "HEAD^{tree}"]).unwrap();
    let tag_before = git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();

    let error = retire_committed_key(
        &fixture.config,
        &fixture.repo,
        "aos-core",
        retirement_options(false),
        &Printer::new(0, true, false),
    )
    .unwrap_err();

    assert!(error.to_string().contains("immutable release tags (1.0.0)"));
    assert_eq!(
        fs::read(fixture.repo.join("keys.toml")).unwrap(),
        roster_before
    );
    assert_eq!(
        fs::read(fixture.repo.join(".git/config")).unwrap(),
        config_before
    );
    assert_eq!(
        fs::read(fixture.repo.join(".git/index")).unwrap(),
        index_before
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "HEAD"]).unwrap(),
        head_before
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "HEAD^{tree}"]).unwrap(),
        tree_before
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap(),
        tag_before
    );
    assert!(
        git(&fixture.repo, &["status", "--porcelain"])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn explicit_revocation_preserves_release_identity_and_removes_trust() {
    let fixture = retirement_fixture();
    sign_tag(
        &fixture.repo,
        "1.0.0",
        "HEAD",
        None,
        fixture.old.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    let tag_before = git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();

    retire_committed_key(
        &fixture.config,
        &fixture.repo,
        "aos-core",
        retirement_options(true),
        &Printer::new(0, true, false),
    )
    .unwrap();

    let roster = keys::load_keys_toml(&fixture.repo).unwrap().unwrap();
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.active[0].id, "survivor");
    assert_eq!(roster.revoked[0].id, "old");
    assert_eq!(
        roster.revoked[0].key.as_deref(),
        Some(fixture.old.trusted_key.as_str())
    );
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap(),
        tag_before
    );
    assert!(
        !verify_tag_signature(&fixture.repo, "1.0.0", &[fixture.survivor.trusted_key]).unwrap()
    );
}

#[test]
fn retirement_without_impacted_release_commits_normally() {
    let fixture = retirement_fixture();
    sign_tag(
        &fixture.repo,
        "1.0.0",
        "HEAD",
        None,
        fixture.survivor.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    let tag_before = git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();

    retire_committed_key(
        &fixture.config,
        &fixture.repo,
        "aos-core",
        retirement_options(false),
        &Printer::new(0, true, false),
    )
    .unwrap();

    let roster = keys::load_keys_toml(&fixture.repo).unwrap().unwrap();
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.revoked[0].id, "old");
    assert_eq!(
        git(&fixture.repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap(),
        tag_before
    );
    assert!(verify_tag_signature(&fixture.repo, "1.0.0", &[fixture.survivor.trusted_key]).unwrap());
}
