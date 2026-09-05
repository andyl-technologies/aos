//! Tests for registry status, changes, branches, commits, and remote synchronization.

use super::{git_ref_exists, remote_diff_base};
use crate::registry_ops::git::git;
use std::fs;
use tempfile::TempDir;

#[test]
fn remote_diff_base_uses_pushed_current_branch_without_origin_head() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    let origin = tmp.path().join("origin.git");
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
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();
    git(
        tmp.path(),
        &[
            "init",
            "--bare",
            "--object-format=sha256",
            origin.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    )
    .unwrap();
    git(&repo, &["push", "origin", "main"]).unwrap();

    assert!(!git_ref_exists(&repo, "origin/HEAD").unwrap());
    assert_eq!(remote_diff_base(&repo).unwrap(), "origin/main");
}
