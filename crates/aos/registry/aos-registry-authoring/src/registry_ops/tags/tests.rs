//! Tests for immutable release references and mutable maintenance tags.

use super::{ensure_release_tag_absent, sign_tag};
use crate::registry_ops::git::git;
use crate::registry_ops::test_support::{TestSigningFixture, write_seeded_signing_key};
use aos_registry_client::security::verify_tag_signature;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn signing_repo() -> (TempDir, PathBuf, TestSigningFixture, TestSigningFixture) {
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
    git(&repo, &["config", "user.name", "Registry Maintainer"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [29u8; 32], "key_a");
    let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [30u8; 32], "key_b");
    (tmp, repo, key_a, key_b)
}

#[test]
fn signed_semver_tags_cannot_be_replaced_even_with_force() {
    let (_tmp, repo, key_a, key_b) = signing_repo();
    for name in [
        "1.0.0",
        "1.0.1-rc.1",
        "1.0.1+build.7",
        "v1.2.3",
        "2026.02",
        "v01.02.03",
    ] {
        sign_tag(
            &repo,
            name,
            "HEAD",
            None,
            key_a.private_key.to_str().unwrap(),
            false,
        )
        .unwrap();
        let refname = format!("refs/tags/{name}");
        let before = git(&repo, &["rev-parse", &refname]).unwrap();
        let config_before = fs::read(repo.join(".git/config")).unwrap();

        // The identity guard must run before target resolution and key loading.
        let error =
            sign_tag(&repo, name, "missing-target", None, "/missing/key", true).unwrap_err();

        assert!(error.to_string().contains("immutable"));
        assert_eq!(git(&repo, &["rev-parse", &refname]).unwrap(), before);
        assert_eq!(fs::read(repo.join(".git/config")).unwrap(), config_before);
        assert!(
            verify_tag_signature(&repo, name, std::slice::from_ref(&key_a.trusted_key)).unwrap()
        );
        assert!(
            !verify_tag_signature(&repo, name, std::slice::from_ref(&key_b.trusted_key)).unwrap()
        );
    }
}

#[test]
fn unsigned_and_lightweight_semver_tags_cannot_be_repaired_in_place() {
    let (_tmp, repo, _key_a, key_b) = signing_repo();
    let git_repo = git2::Repository::open(&repo).unwrap();
    let target = git_repo.revparse_single("HEAD").unwrap();
    git_repo.tag_lightweight("1.0.0", &target, false).unwrap();
    git_repo
        .tag(
            "1.0.1",
            &target,
            &git_repo.signature().unwrap(),
            "unsigned release",
            false,
        )
        .unwrap();

    git_repo.tag_lightweight("v1.2.3", &target, false).unwrap();
    git_repo.tag_lightweight("2026.02", &target, false).unwrap();

    for name in ["1.0.0", "1.0.1", "v1.2.3", "2026.02"] {
        let refname = format!("refs/tags/{name}");
        let before = git(&repo, &["rev-parse", &refname]).unwrap();

        let error = sign_tag(
            &repo,
            name,
            "HEAD",
            None,
            key_b.private_key.to_str().unwrap(),
            true,
        )
        .unwrap_err();

        assert!(error.to_string().contains("immutable"));
        assert_eq!(git(&repo, &["rev-parse", &refname]).unwrap(), before);
        assert!(ensure_release_tag_absent(&repo, name).is_err());
    }
}

#[test]
fn maintenance_tags_can_be_resigned() {
    let (_tmp, repo, key_a, key_b) = signing_repo();
    sign_tag(
        &repo,
        "maintenance",
        "HEAD",
        None,
        key_a.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();
    let before = git(&repo, &["rev-parse", "refs/tags/maintenance"]).unwrap();

    sign_tag(
        &repo,
        "maintenance",
        "HEAD",
        None,
        key_b.private_key.to_str().unwrap(),
        true,
    )
    .unwrap();

    assert_ne!(
        git(&repo, &["rev-parse", "refs/tags/maintenance"]).unwrap(),
        before
    );
    assert!(verify_tag_signature(&repo, "maintenance", &[key_b.trusted_key]).unwrap());
    assert!(!verify_tag_signature(&repo, "maintenance", &[key_a.trusted_key]).unwrap());
}
