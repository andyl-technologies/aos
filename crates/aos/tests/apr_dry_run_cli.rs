//! Regression coverage for the global `apr --dry-run` flag.
//!
//! `--dry-run` is declared `global = true` on the `apr` CLI, so it parses for
//! every subcommand. Only `apr cache` ever read it: `apr create` accepted the
//! flag, announced "Registry '<name>' created at …", and created and
//! SSH-signed the registry anyway. A subsequent real invocation then failed
//! with "already exists", leaving the operator with a trust anchor they had
//! only asked to preview.
//!
//! A registry root commit is pinned by every later release plan, so creating
//! one unintentionally is not a cosmetic slip. These tests pin both halves of
//! the fix: `create` honors the flag, and any subcommand that does not
//! implement it refuses rather than mutating behind a preview.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result};
use tempfile::TempDir;

/// The path `apr create <name>` writes a registry to, under an isolated `HOME`.
fn registry_path(home: &Path, name: &str) -> std::path::PathBuf {
    home.join(".local/share/apm/registries").join(name)
}

/// Spawn `apr` against an isolated `HOME` with a committer identity present,
/// so nothing fails for the unrelated reason of a missing maintainer identity.
fn apr(home: &Path, args: &[&str]) -> Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .env("USER", "dry-run-test")
        .env("LOGNAME", "dry-run-test")
        .env("GIT_AUTHOR_NAME", "Dry Run Test")
        .env("GIT_AUTHOR_EMAIL", "dry-run@example.com")
        .env("GIT_COMMITTER_NAME", "Dry Run Test")
        .env("GIT_COMMITTER_EMAIL", "dry-run@example.com")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .args(args)
        .output()
        .with_context(|| format!("spawning apr {}", args.join(" ")))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The core regression: a dry-run `create` reports success and leaves the
/// filesystem untouched.
#[test]
fn dry_run_create_writes_nothing() -> Result<()> {
    let home = TempDir::new()?;

    let output = apr(home.path(), &["create", "demo", "--dry-run"])?;

    assert!(
        output.status.success(),
        "dry-run create should succeed:\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output),
    );
    assert!(
        !registry_path(home.path(), "demo").exists(),
        "dry-run create must not create the registry directory, but {} exists",
        registry_path(home.path(), "demo").display(),
    );
    // Human-readable printer output goes to stderr; stdout carries only the
    // JSON document in `--json` mode.
    let text = stderr(&output);
    assert!(
        text.contains("Would create registry 'demo'"),
        "dry run should describe the registry it would create, got:\n{text}"
    );
    assert!(
        text.contains("nothing was written"),
        "dry run should state plainly that it wrote nothing, got:\n{text}"
    );
    Ok(())
}

/// The exact operator-visible symptom of the bug: a dry run consumed the
/// registry name, so the real invocation that followed it failed.
#[test]
fn dry_run_create_leaves_the_name_available() -> Result<()> {
    let home = TempDir::new()?;

    let preview = apr(home.path(), &["create", "demo", "--dry-run"])?;
    assert!(preview.status.success(), "dry run should succeed");

    let real = apr(home.path(), &["create", "demo"])?;

    assert!(
        real.status.success(),
        "create after a dry run must still succeed, but it failed:\nstdout:\n{}\nstderr:\n{}",
        stdout(&real),
        stderr(&real),
    );
    assert!(
        registry_path(home.path(), "demo")
            .join("keys.toml")
            .is_file(),
        "the real create should have written the registry"
    );
    Ok(())
}

/// A dry run is a preview of a real run, not a blanket success: preconditions
/// that would fail the real command must fail the preview identically.
#[test]
fn dry_run_create_still_reports_preconditions() -> Result<()> {
    let home = TempDir::new()?;
    apr(home.path(), &["create", "demo"])?;

    let output = apr(home.path(), &["create", "demo", "--dry-run"])?;

    assert!(
        !output.status.success(),
        "dry run must refuse a name that is already taken"
    );
    let text = stderr(&output);
    assert!(
        text.contains("already exists"),
        "expected the already-exists error, got:\n{text}"
    );
    Ok(())
}

/// A trust-seeded registry needs a signing key. The preview must reject that
/// combination too, rather than deferring the discovery to the real run.
#[test]
fn dry_run_create_rejects_a_trust_key_without_a_signing_key() -> Result<()> {
    let home = TempDir::new()?;

    let output = apr(
        home.path(),
        &[
            "create",
            "demo",
            "--trust-key",
            "demo:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--trust-key-id",
            "initial",
            "--dry-run",
        ],
    )?;

    assert!(
        !output.status.success(),
        "dry run must reject a seeded roster with no signing key"
    );
    assert!(
        !registry_path(home.path(), "demo").exists(),
        "a rejected dry run must not leave a registry behind"
    );
    Ok(())
}

/// JSON consumers must be able to tell a preview from a created registry.
#[test]
fn dry_run_create_marks_the_json_preview() -> Result<()> {
    let home = TempDir::new()?;

    let output = apr(home.path(), &["create", "demo", "--dry-run", "--json"])?;
    assert!(output.status.success(), "dry-run create should succeed");

    let value: serde_json::Value = serde_json::from_str(stdout(&output).trim())
        .context("dry-run create should emit a single JSON document")?;

    assert_eq!(value["dry_run"], serde_json::json!(true));
    assert_eq!(value["registry"], serde_json::json!("demo"));
    // `head` would be a commit id that does not exist; its absence is what
    // stops a consumer from treating the preview as a created registry.
    assert!(
        value.get("head").is_none(),
        "a preview must not report a head commit, got: {value}"
    );
    Ok(())
}

/// Read-only subcommands refuse the flag rather than accepting it as a no-op,
/// so `--dry-run` never implies a command was given preview handling it lacks.
#[test]
fn dry_run_is_refused_by_read_only_subcommands() -> Result<()> {
    let home = TempDir::new()?;

    let output = apr(home.path(), &["list", "--dry-run"])?;

    assert!(
        !output.status.success(),
        "a read-only subcommand must refuse the flag"
    );
    let text = stderr(&output);
    assert!(
        text.contains("--dry-run is not implemented"),
        "expected the unsupported-dry-run refusal, got:\n{text}"
    );
    Ok(())
}

/// `apr commit --dry-run` reports the commit it would make and leaves HEAD
/// exactly where it was.
#[test]
fn dry_run_commit_leaves_head_untouched() -> Result<()> {
    let home = TempDir::new()?;
    let created = apr(home.path(), &["create", "demo"])?;
    assert!(created.status.success(), "fixture create should succeed");

    let registry = registry_path(home.path(), "demo");
    std::fs::write(
        registry.join("registry.toml"),
        "[registry]\nname = \"demo\"\n",
    )?;
    let before = head_commit(&registry)?;

    let output = apr(
        home.path(),
        &[
            "commit",
            "registry.toml",
            "-m",
            "preview only",
            "--registry",
            "demo",
            "--dry-run",
        ],
    )?;

    assert!(
        output.status.success(),
        "dry-run commit should succeed:\nstderr:\n{}",
        stderr(&output),
    );
    assert_eq!(
        head_commit(&registry)?,
        before,
        "a dry-run commit must not move HEAD"
    );
    let text = stderr(&output);
    assert!(
        text.contains("Would commit"),
        "expected a commit preview, got:\n{text}"
    );
    Ok(())
}

/// `apr tag --dry-run` creates no tag.
#[test]
fn dry_run_tag_creates_no_tag() -> Result<()> {
    let home = TempDir::new()?;
    let created = apr(home.path(), &["create", "demo"])?;
    assert!(created.status.success(), "fixture create should succeed");

    let output = apr(
        home.path(),
        &["tag", "v1.0.0", "--registry", "demo", "--dry-run"],
    )?;

    // Whether this reaches the preview or fails resolving a signing key, the
    // one thing it must never do is leave a tag behind.
    let tags = git_output(&registry_path(home.path(), "demo"), &["tag", "--list"])?;
    assert!(
        tags.trim().is_empty(),
        "a dry-run tag must not create a tag, found:\n{tags}"
    );
    if output.status.success() {
        let text = stderr(&output);
        assert!(
            text.contains("Would create signed tag"),
            "expected a tag preview, got:\n{text}"
        );
    }
    Ok(())
}

/// Read the `HEAD` commit id of a registry clone, hermetic against the host
/// git configuration.
fn head_commit(repo: &Path) -> Result<String> {
    git_output(repo, &["rev-parse", "HEAD"])
}

/// Run a read-only git command against `repo`, insulated from host config.
fn git_output(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
