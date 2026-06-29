//! Regression coverage for how `apr create` discovers the maintainer's commit
//! identity from the host git configuration.
//!
//! Registry commits record who published, so `apr create` reads `user.name`
//! and `user.email` from the host config exactly as `git config --global`
//! resolves them — which spans *two* files: the classic `~/.gitconfig` and the
//! XDG `$XDG_CONFIG_HOME/git/config` (defaulting to `~/.config/git/config`).
//!
//! libgit2's `Config::find_global()` locates only `~/.gitconfig`, so the
//! migration that swapped the git CLI for libgit2 (commit 4fe6a54ac) silently
//! dropped the XDG file and falsely reported `user.email` unset for
//! home-manager-style setups that keep the identity solely under
//! `~/.config/git/config`.
//!
//! Every other `apr` CLI test injects `GIT_AUTHOR_*`/`GIT_COMMITTER_*` into the
//! environment, which short-circuits the host-config read entirely — which is
//! why the regression slipped through. These tests deliberately leave those
//! variables unset so the host git config is the only identity source.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result};
use tempfile::TempDir;

/// Spawn `apr create <name>` against an isolated `HOME`, with no commit
/// identity in the environment.
///
/// `GIT_AUTHOR_*`/`GIT_COMMITTER_*` are stripped so the identity must come from
/// the host git config, and the `XDG_*` overrides are stripped so the child
/// resolves `~/.config/git/config` and writes the registry under
/// `$HOME/.local/share`, both inside the test's temporary `HOME`.
fn apr_create(home: &Path, name: &str) -> Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .env("USER", "host-identity-test")
        .env("LOGNAME", "host-identity-test")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .args(["create", name])
        .output()
        .context("spawning apr create")
}

/// Write a git identity into the XDG config (`<home>/.config/git/config`) and
/// deliberately leave `<home>/.gitconfig` absent — the exact layout that
/// regressed.
fn write_xdg_identity(home: &Path, name: &str, email: &str) -> Result<()> {
    let config = home.join(".config/git/config");
    std::fs::create_dir_all(config.parent().expect("config has a parent"))?;
    std::fs::write(
        &config,
        format!("[user]\n\tname = {name}\n\temail = {email}\n"),
    )?;
    Ok(())
}

/// An identity kept only in the XDG config is enough for `apr create`: the
/// registry is created and its initial commit carries that identity.
#[test]
fn apr_create_reads_identity_from_xdg_config() -> Result<()> {
    let home = TempDir::new()?;
    write_xdg_identity(home.path(), "Louis Opter", "louis@andyl.com")?;

    let output = apr_create(home.path(), "demo")?;
    assert!(
        output.status.success(),
        "apr create should succeed with an XDG-only identity:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The identity must have flowed all the way into the commit, not merely
    // satisfied the pre-flight check.
    let repo = home.path().join(".local/share/apm/registries/demo");
    let author = head_author(&repo)?;
    assert_eq!(
        author, "Louis Opter <louis@andyl.com>",
        "initial commit should be attributed to the XDG identity"
    );
    Ok(())
}

/// With no identity anywhere — no host config and no environment override —
/// `apr create` refuses up front with the maintainer-identity setup error.
/// This pins the failure mode the XDG read must avoid and proves the success
/// above genuinely depended on the host config.
#[test]
fn apr_create_without_any_identity_reports_setup_error() -> Result<()> {
    let home = TempDir::new()?;

    let output = apr_create(home.path(), "demo")?;
    assert!(
        !output.status.success(),
        "apr create must refuse without a commit identity"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("git user.email is not set"),
        "expected the maintainer-identity setup error, got:\n{stderr}"
    );
    Ok(())
}

/// Read the `HEAD` commit author of `repo` as `Name <email>`, hermetic against
/// any ambient host git config so the assertion reflects only what `apr create`
/// recorded.
fn head_author(repo: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["log", "-1", "--format=%an <%ae>"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .context("reading HEAD author")?;
    anyhow::ensure!(
        output.status.success(),
        "git log failed:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
