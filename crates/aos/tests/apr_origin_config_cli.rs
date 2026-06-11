//! End-to-end coverage for `apr origin config` and the persisted
//! upload-default fallback used by `apr origin upload`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

#[test]
fn apr_origin_config_requires_registry_config() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    fs::create_dir_all(&home)?;

    let err = run_apr_err(
        &home,
        &[
            "origin",
            "config",
            "--upload-url",
            "s3://bucket/",
            "--registry",
            "core",
        ],
    )?;
    let text = output_text(&err);
    assert!(text.contains("has no config"), "{text}");
    assert!(text.contains("add <url>"), "{text}");

    Ok(())
}

#[test]
fn apr_origin_config_sets_shows_and_unsets_upload_defaults() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    write_registry_config(&home, "core")?;
    let config_path = home.join(".config/apm/registries.d/core.toml");

    // Set: destinations plus an S3 endpoint.
    let output = run_apr(
        &home,
        &[
            "origin",
            "config",
            "--upload-url",
            "s3://bucket/",
            "--upload-url",
            "file:///mirror",
            "--s3-endpoint",
            "https://s3.example",
            "--registry",
            "core",
        ],
    )?;
    assert!(output.contains("s3://bucket/"), "{output}");

    let config = fs::read_to_string(&config_path)?;
    assert!(config.contains("[registry.upload_auth]"), "{config}");
    assert!(
        config.contains("upload_urls = [\"s3://bucket/\", \"file:///mirror\"]"),
        "{config}",
    );
    assert!(
        config.contains("s3_endpoint = \"https://s3.example\""),
        "{config}"
    );
    // User-edited fields survive the rewrite.
    assert!(config.contains("url = \"file:///dev/null\""), "{config}");

    // Show: no setter flags prints the persisted defaults.
    let output = run_apr(&home, &["origin", "config", "--registry", "core"])?;
    assert!(output.contains("s3://bucket/"), "{output}");
    assert!(output.contains("https://s3.example"), "{output}");

    // Unset one field, the other survives.
    run_apr(
        &home,
        &[
            "origin",
            "config",
            "--unset",
            "s3-endpoint",
            "--registry",
            "core",
        ],
    )?;
    let config = fs::read_to_string(&config_path)?;
    assert!(!config.contains("s3_endpoint"), "{config}");
    assert!(config.contains("upload_urls"), "{config}");

    // Unsetting the last field removes the whole section.
    run_apr(
        &home,
        &[
            "origin",
            "config",
            "--unset",
            "upload-urls",
            "--registry",
            "core",
        ],
    )?;
    let config = fs::read_to_string(&config_path)?;
    assert!(!config.contains("[registry.upload_auth]"), "{config}");

    let output = run_apr(&home, &["origin", "config", "--registry", "core"])?;
    assert!(output.contains("No upload defaults configured"), "{output}");

    Ok(())
}

#[test]
fn apr_origin_config_rejects_setting_and_unsetting_the_same_field() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    write_registry_config(&home, "core")?;

    let err = run_apr_err(
        &home,
        &[
            "origin",
            "config",
            "--s3-endpoint",
            "https://s3.example",
            "--unset",
            "s3-endpoint",
            "--registry",
            "core",
        ],
    )?;
    let text = output_text(&err);
    assert!(
        text.contains("cannot both set and --unset 's3-endpoint'"),
        "{text}",
    );

    // Nothing was persisted by the refused invocation.
    let config = fs::read_to_string(home.join(".config/apm/registries.d/core.toml"))?;
    assert!(!config.contains("s3_endpoint"), "{config}");

    Ok(())
}

#[test]
fn apr_origin_upload_falls_back_to_persisted_upload_urls() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    if !git_supports_sha256(&home)? {
        eprintln!("skipping apr origin upload e2e: git cannot initialize a sha256 repository");
        return Ok(());
    }
    write_registry_config(&home, "core")?;
    run_apr(&home, &["create", "core"])?;

    // With neither flags nor persisted defaults the upload is refused,
    // pointing at both ways to provide a destination.
    let err = run_apr_err(&home, &["origin", "upload", "--registry", "core"])?;
    let text = output_text(&err);
    assert!(text.contains("--upload-url"), "{text}");
    assert!(text.contains("origin config"), "{text}");

    // Persist a file:// destination, then upload without any flag.
    let upload_dir = tmp.path().join("origin-upload");
    fs::create_dir_all(&upload_dir)?;
    let upload_url = format!("file://{}", upload_dir.display());
    run_apr(
        &home,
        &[
            "origin",
            "config",
            "--upload-url",
            &upload_url,
            "--registry",
            "core",
        ],
    )?;
    let output = run_apr(&home, &["origin", "upload", "--registry", "core"])?;
    assert!(output.contains("Uploaded"), "{output}");
    assert!(
        upload_dir.join("HEAD").exists(),
        "uploaded origin surface is missing HEAD in {}",
        upload_dir.display(),
    );

    Ok(())
}

/// Write a minimal user-scope registry config so `--registry core` resolves.
fn write_registry_config(home: &Path, name: &str) -> Result<()> {
    let dir = home.join(".config/apm/registries.d");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join(format!("{name}.toml")),
        format!("[registry]\nname = \"{name}\"\nurl = \"file:///dev/null\"\n"),
    )?;
    Ok(())
}

fn git_supports_sha256(home: &Path) -> Result<bool> {
    let probe = home.join(".sha256-probe");
    fs::create_dir_all(&probe)?;
    let init = Command::new("git")
        .args(["init", "--object-format=sha256"])
        .current_dir(&probe)
        .output()
        .context("running git init --object-format=sha256")?;
    Ok(init.status.success())
}

/// Spawn `apr` against an isolated `HOME`, with a committer identity in the
/// environment: registry commits refuse to run without one.
fn apr_command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apr"));
    cmd.env("HOME", home)
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com");
    cmd
}

fn run_apr(home: &Path, args: &[&str]) -> Result<String> {
    let output = apr_command(home)
        .args(args)
        .output()
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "apr {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output_text(&output))
}

fn run_apr_err(home: &Path, args: &[&str]) -> Result<Output> {
    let output = apr_command(home)
        .args(args)
        .output()
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if output.status.success() {
        bail!("apr {} unexpectedly succeeded", args.join(" "));
    }
    Ok(output)
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}
