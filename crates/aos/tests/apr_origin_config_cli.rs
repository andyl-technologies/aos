//! End-to-end coverage for `apr origin config` and the persisted
//! upload-default fallback used by `apr origin upload`.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use aos_package::security::parse_signing_key;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

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

#[test]
fn apr_commit_refuses_unsafe_paths_and_pre_staged_changes() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    if !git_supports_sha256(&home)? {
        eprintln!("skipping apr commit boundary test: git cannot initialize a sha256 repository");
        return Ok(());
    }
    run_apr(&home, &["create", "core"])?;
    let registry = registry_dir(&home, "core");
    write_fixture_package(&registry)?;

    let unsafe_path = run_apr_err(
        &home,
        &[
            "commit",
            "../outside",
            "--message",
            "unsafe path",
            "--registry",
            "core",
        ],
    )?;
    assert!(
        output_text(&unsafe_path).contains("registry-relative path without '.' or '..'"),
        "{}",
        output_text(&unsafe_path),
    );

    git_stdout(
        &registry,
        &["add", "packages/f/fixture-tool.toml"],
        "staging fixture before apr commit",
    )?;
    let staged = run_apr_err(
        &home,
        &[
            "commit",
            "packages/f/fixture-tool.toml",
            "--message",
            "must not absorb staged state",
            "--registry",
            "core",
        ],
    )?;
    assert!(
        output_text(&staged).contains("already has staged changes"),
        "{}",
        output_text(&staged),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_add_authoring_clone_supports_release_upload_workflow() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let seed_home = tmp.path().join("seed-home");
    let maintainer_home = tmp.path().join("maintainer-home");
    let consumer_home = tmp.path().join("consumer-home");
    let consumer_system_dir = tmp.path().join("consumer-etc-apm");
    if !git_supports_sha256(&seed_home)? {
        eprintln!(
            "skipping apr add authoring clone e2e: git cannot initialize a sha256 repository"
        );
        return Ok(());
    }

    run_apr(&seed_home, &["create", "origin-default-reg"])?;
    let seed_registry = registry_dir(&seed_home, "origin-default-reg");
    let default_branch = git_stdout(
        &seed_registry,
        &["symbolic-ref", "--short", "HEAD"],
        "reading seed registry branch",
    )?;
    let remote = tmp.path().join("origin-default.git");
    git_stdout(
        tmp.path(),
        &[
            "init",
            "--bare",
            "--object-format=sha256",
            remote.to_str().unwrap_or_default(),
        ],
        "initializing bare registry origin",
    )?;
    git_stdout(
        &seed_registry,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().unwrap_or_default(),
        ],
        "adding registry origin",
    )?;
    git_stdout(
        &seed_registry,
        &["push", "origin", &default_branch],
        "pushing seed registry",
    )?;

    let remote_url = format!("file://{}", remote.display());
    run_apr(
        &maintainer_home,
        &[
            "add",
            "--no-verify",
            &remote_url,
            "--name",
            "origin-default-reg",
            "--branch",
            &default_branch,
        ],
    )?;

    let maintainer_registry = registry_dir(&maintainer_home, "origin-default-reg");
    assert!(
        maintainer_registry.join(".git").is_dir(),
        "apr add should leave an authoring clone at {}",
        maintainer_registry.display(),
    );
    let inside = git_stdout(
        &maintainer_registry,
        &["rev-parse", "--is-inside-work-tree"],
        "checking maintainer clone worktree",
    )?;
    assert_eq!(inside, "true");
    let branch = git_stdout(
        &maintainer_registry,
        &["branch", "--show-current"],
        "checking maintainer clone branch",
    )?;
    assert_eq!(branch, default_branch);

    write_fixture_package(&maintainer_registry)?;
    configure_fixture_git_identity(&maintainer_registry)?;
    git_stdout(
        &maintainer_registry,
        &["add", "packages/f/fixture-tool.toml"],
        "staging fixture package",
    )?;
    git_stdout(
        &maintainer_registry,
        &["commit", "-m", "publish fixture package metadata"],
        "committing fixture package",
    )?;

    run_apr(
        &maintainer_home,
        &["status", "--registry", "origin-default-reg"],
    )?;
    run_apr(
        &maintainer_home,
        &[
            "keys",
            "generate",
            "release",
            "--registry",
            "origin-default-reg",
        ],
    )?;
    let release_key = maintainer_home.join(".config/apm/keys/origin-default-reg-release.key");
    assert!(
        release_key.exists(),
        "apr keys generate should write {}",
        release_key.display(),
    );

    let upload_dir = tmp.path().join("origin-default-upload");
    let upload_url = format!("file://{}", upload_dir.display());
    let release = run_apr(
        &maintainer_home,
        &[
            "release",
            "1.0.0",
            "--registry",
            "origin-default-reg",
            "--key",
            release_key.to_str().context("release key path utf-8")?,
        ],
    )?;
    assert!(
        release.contains("Released origin-default-reg 1.0.0"),
        "{release}"
    );
    // The fixture's placeholder store path can't be cached, so the release is
    // local; `apr origin upload` publishes the git origin for the consumer.
    run_apr(
        &maintainer_home,
        &[
            "origin",
            "upload",
            "--registry",
            "origin-default-reg",
            "--upload-url",
            &upload_url,
        ],
    )?;
    git_stdout(
        &maintainer_registry,
        &["rev-parse", "1.0.0^{tag}"],
        "checking release tag",
    )?;
    assert!(
        upload_dir.join("HEAD").exists(),
        "uploaded origin is missing HEAD in {}",
        upload_dir.display(),
    );
    assert!(
        upload_dir
            .join("releases/1/0/0/objects/info/packs")
            .exists(),
        "uploaded origin is missing release pack metadata in {}",
        upload_dir.display(),
    );

    let server = StaticHttpServer::spawn(upload_dir.clone()).await?;
    let uploaded_origin_url = server.base_url();
    let added = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &[
            "--json",
            "registry",
            "add",
            &uploaded_origin_url,
            "--no-verify",
            "--name",
            "origin-default-reg",
            "--branch",
            &default_branch,
        ],
        "registry add",
    )?;
    assert_eq!(added["action"], "registry_add");
    assert_eq!(added["registry"], "origin-default-reg");
    assert_eq!(added["synced"], true, "{added}");
    assert_eq!(added["packages"], 1, "{added}");

    let listed = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "list", "--registry", "origin-default-reg"],
        "list",
    )?;
    let entries = listed
        .as_array()
        .context("package list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["registry"], "origin-default-reg");
    assert_eq!(entries[0]["version"], "1.0.0");

    write_fixture_package_version(&maintainer_registry, "1.1.0")?;
    git_stdout(
        &maintainer_registry,
        &["add", "packages/f/fixture-tool.toml"],
        "staging fixture package update",
    )?;
    git_stdout(
        &maintainer_registry,
        &["commit", "-m", "publish fixture package update"],
        "committing fixture package update",
    )?;
    let release = run_apr(
        &maintainer_home,
        &[
            "release",
            "1.1.0",
            "--registry",
            "origin-default-reg",
            "--key",
            release_key.to_str().context("release key path utf-8")?,
        ],
    )?;
    assert!(
        release.contains("Released origin-default-reg 1.1.0"),
        "{release}"
    );
    run_apr(
        &maintainer_home,
        &[
            "origin",
            "upload",
            "--registry",
            "origin-default-reg",
            "--upload-url",
            &upload_url,
        ],
    )?;

    let updated = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "update", "--registry", "origin-default-reg"],
        "update uploaded origin",
    )?;
    assert_eq!(updated["action"], "update");
    assert_eq!(updated["registry"], "origin-default-reg");
    assert_eq!(updated["updated"], 1, "{updated}");
    let registries = updated["registries"]
        .as_array()
        .context("update JSON should contain registries array")?;
    assert_eq!(registries.len(), 1, "{updated}");
    assert_eq!(registries[0]["registry"], "origin-default-reg");
    assert_eq!(registries[0]["status"], "updated");
    assert_eq!(registries[0]["packages"], 1, "{updated}");
    assert_eq!(registries[0]["updated"], 1, "{updated}");

    let listed = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "list", "--registry", "origin-default-reg"],
        "list after uploaded origin update",
    )?;
    let entries = listed
        .as_array()
        .context("updated package list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["registry"], "origin-default-reg");
    assert_eq!(entries[0]["version"], "1.1.0");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_release_channel_upload_supports_verified_consumer_sync() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let maintainer_home = tmp.path().join("maintainer-home");
    let consumer_home = tmp.path().join("consumer-home");
    let consumer_system_dir = tmp.path().join("consumer-etc-apm");
    if !git_supports_sha256(&maintainer_home)? {
        eprintln!("skipping signed channel e2e: git cannot initialize a sha256 repository");
        return Ok(());
    }

    let key_output = run_apr(
        &maintainer_home,
        &["keys", "generate", "initial", "--registry", "signed-reg"],
    )?;
    let trust_key = extract_public_key(&key_output)?;
    let key_path = maintainer_home.join(".config/apm/keys/signed-reg-initial.key");

    run_apr(
        &maintainer_home,
        &[
            "create",
            "signed-reg",
            "--trust-key",
            &trust_key,
            "--key",
            key_path.to_str().context("initial key path utf-8")?,
        ],
    )?;

    let maintainer_registry = registry_dir(&maintainer_home, "signed-reg");
    write_fixture_package(&maintainer_registry)?;
    run_apr(
        &maintainer_home,
        &[
            "commit",
            "packages/f/fixture-tool.toml",
            "--message",
            "publish signed fixture package metadata",
            "--registry",
            "signed-reg",
            "--key",
            key_path
                .to_str()
                .context("fixture signing key path utf-8")?,
        ],
    )?;

    let upload_dir = tmp.path().join("signed-reg-upload");
    let upload_url = format!("file://{}", upload_dir.display());
    let release = run_apr(
        &maintainer_home,
        &[
            "release",
            "1.0.0",
            "--registry",
            "signed-reg",
            "--key",
            key_path.to_str().context("release key path utf-8")?,
            "--channel",
            "stable",
            "--init-channel",
        ],
    )?;
    assert!(release.contains("Released signed-reg 1.0.0"), "{release}");
    // Placeholder store path → no cache; publish the git origin (incl. the
    // freshly-initialized channel partitions) with `apr origin upload`.
    run_apr(
        &maintainer_home,
        &[
            "origin",
            "upload",
            "--registry",
            "signed-reg",
            "--upload-url",
            &upload_url,
        ],
    )?;
    assert!(
        upload_dir.join("channels/stable/00").exists(),
        "uploaded signed channel is missing a partition in {}",
        upload_dir.display(),
    );

    let server = StaticHttpServer::spawn(upload_dir.clone()).await?;
    let added = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &[
            "--json",
            "registry",
            "add",
            &server.base_url(),
            "--trust-key",
            &trust_key,
            "--name",
            "signed-reg",
            "--channel",
            "stable",
        ],
        "verified channel registry add",
    )?;
    assert_eq!(added["action"], "registry_add");
    assert_eq!(added["registry"], "signed-reg");
    assert_eq!(added["synced"], true, "{added}");
    assert_eq!(added["packages"], 1, "{added}");
    assert_eq!(added["signing_required"], true, "{added}");
    assert_eq!(added["trusted_key_pinned"], true, "{added}");

    let listed = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "list", "--registry", "signed-reg"],
        "verified channel list",
    )?;
    let entries = listed
        .as_array()
        .context("signed package list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["registry"], "signed-reg");
    assert_eq!(entries[0]["version"], "1.0.0");

    write_fixture_package_version(&maintainer_registry, "1.1.0")?;
    run_apr(
        &maintainer_home,
        &[
            "commit",
            "packages/f/fixture-tool.toml",
            "--message",
            "publish signed fixture package update",
            "--registry",
            "signed-reg",
            "--key",
            key_path
                .to_str()
                .context("fixture signing key path utf-8")?,
        ],
    )?;

    let release = run_apr(
        &maintainer_home,
        &[
            "release",
            "1.1.0",
            "--registry",
            "signed-reg",
            "--key",
            key_path.to_str().context("release key path utf-8")?,
            "--channel",
            "stable",
            "--count",
            "256",
        ],
    )?;
    assert!(release.contains("Released signed-reg 1.1.0"), "{release}");
    assert!(
        release.contains("Advanced channel 'stable' 256 partition(s) to 1.1.0"),
        "{release}",
    );
    run_apr(
        &maintainer_home,
        &[
            "origin",
            "upload",
            "--registry",
            "signed-reg",
            "--upload-url",
            &upload_url,
        ],
    )?;

    let updated = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "update", "--registry", "signed-reg"],
        "verified channel update",
    )?;
    assert_eq!(updated["action"], "update");
    assert_eq!(updated["registry"], "signed-reg");
    assert_eq!(updated["updated"], 1, "{updated}");
    let registries = updated["registries"]
        .as_array()
        .context("verified channel update JSON should contain registries array")?;
    assert_eq!(registries.len(), 1, "{updated}");
    assert_eq!(registries[0]["registry"], "signed-reg");
    assert_eq!(registries[0]["status"], "updated");
    assert_eq!(registries[0]["packages"], 1, "{updated}");
    assert_eq!(registries[0]["updated"], 1, "{updated}");

    let listed = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "list", "--registry", "signed-reg"],
        "verified channel list after advance",
    )?;
    let entries = listed
        .as_array()
        .context("advanced signed package list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["registry"], "signed-reg");
    assert_eq!(entries[0]["version"], "1.1.0");

    let unpublished = run_apr(
        &maintainer_home,
        &[
            "unpublish",
            "fixture-tool",
            "--registry",
            "signed-reg",
            "--key",
            key_path.to_str().context("unpublish key path utf-8")?,
            "--message",
            "retire signed fixture package",
        ],
    )?;
    assert!(
        unpublished.contains("Removed package 'fixture-tool' entirely."),
        "{unpublished}",
    );
    assert!(
        unpublished.contains("Committed: retire signed fixture package"),
        "{unpublished}",
    );
    assert!(
        !maintainer_registry
            .join("packages/f/fixture-tool.toml")
            .exists(),
        "apr unpublish should remove the package file from the authoring clone",
    );
    let commit_message = git_stdout(
        &maintainer_registry,
        &["log", "-1", "--pretty=%B"],
        "checking signed unpublish commit message",
    )?;
    assert_eq!(commit_message, "retire signed fixture package");

    let release = run_apr(
        &maintainer_home,
        &[
            "release",
            "1.2.0",
            "--registry",
            "signed-reg",
            "--key",
            key_path.to_str().context("release key path utf-8")?,
            "--channel",
            "stable",
            "--count",
            "256",
            "--upload-url",
            &upload_url,
        ],
    )?;
    assert!(release.contains("Released signed-reg 1.2.0"), "{release}");
    assert!(
        release.contains("Advanced channel 'stable' 256 partition(s) to 1.2.0"),
        "{release}",
    );
    git_stdout(
        &maintainer_registry,
        &["rev-parse", "1.2.0^{tag}"],
        "checking post-unpublish release tag",
    )?;
    assert!(
        upload_dir
            .join("releases/1/2/0/objects/info/packs")
            .exists(),
        "uploaded origin is missing post-unpublish release pack metadata in {}",
        upload_dir.display(),
    );

    let updated = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "update", "--registry", "signed-reg"],
        "verified channel update after unpublish",
    )?;
    assert_eq!(updated["action"], "update");
    assert_eq!(updated["registry"], "signed-reg");
    assert_eq!(updated["updated"], 1, "{updated}");
    let registries = updated["registries"]
        .as_array()
        .context("post-unpublish update JSON should contain registries array")?;
    assert_eq!(registries.len(), 1, "{updated}");
    assert_eq!(registries[0]["registry"], "signed-reg");
    assert_eq!(registries[0]["status"], "updated");
    assert_eq!(registries[0]["packages"], 0, "{updated}");
    assert_eq!(registries[0]["added"], 0, "{updated}");
    assert_eq!(registries[0]["updated"], 0, "{updated}");
    assert_eq!(registries[0]["removed"], 1, "{updated}");

    let listed = run_aos_package_json(
        &consumer_home,
        &consumer_system_dir,
        &["--json", "list", "--registry", "signed-reg"],
        "verified channel list after unpublish",
    )?;
    assert_eq!(
        listed
            .as_array()
            .context("post-unpublish package list JSON should be an array")?
            .len(),
        0,
        "{listed}",
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

fn registry_dir(home: &Path, name: &str) -> std::path::PathBuf {
    home.join(".local/share/apm/registries").join(name)
}

fn write_fixture_package(registry: &Path) -> Result<()> {
    write_fixture_package_version(registry, "1.0.0")
}

fn write_fixture_package_version(registry: &Path, version: &str) -> Result<()> {
    let package_dir = registry.join("packages/f");
    fs::create_dir_all(&package_dir)?;
    fs::write(
        package_dir.join("fixture-tool.toml"),
        fixture_package_toml("fixture-tool", version),
    )?;
    Ok(())
}

fn fixture_package_toml(name: &str, version: &str) -> String {
    let platform = current_platform();
    let mut toml = format!(
        r#"[package]
name = "{name}"
description = "Maintainer workflow fixture"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "{version}"

{}
"#,
        fixture_platform_toml("x86_64-linux", name, version),
    );
    if platform != "x86_64-linux" {
        toml.push('\n');
        toml.push_str(&fixture_platform_toml(&platform, name, version));
    }
    toml
}

fn fixture_platform_toml(platform: &str, name: &str, version: &str) -> String {
    format!(
        r#"[versions.platforms.{platform}]
store_path = "/nix/store/00000000000000000000000000000000-{name}-{version}"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#,
    )
}

fn current_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7l",
        other => other,
    };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => other,
    };
    format!("{arch}-{os}")
}

fn configure_fixture_git_identity(registry: &Path) -> Result<()> {
    git_stdout(
        registry,
        &["config", "user.name", "Registry Test"],
        "configuring fixture git user",
    )?;
    git_stdout(
        registry,
        &["config", "user.email", "registry@example.com"],
        "configuring fixture git email",
    )?;
    git_stdout(
        registry,
        &["config", "commit.gpgsign", "false"],
        "disabling fixture commit signing",
    )?;
    Ok(())
}

fn extract_public_key(output: &str) -> Result<String> {
    output
        .lines()
        .filter_map(|line| {
            let value = line.split_whitespace().last()?;
            parse_signing_key(value).ok().map(|_| value.to_string())
        })
        .next()
        .with_context(|| format!("no public key line in output:\n{output}"))
}

fn git_stdout(cwd: &Path, args: &[&str], context: &str) -> Result<String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test");
    let output = command
        .output()
        .with_context(|| format!("{context}: git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "{context} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_aos_package_json(
    home: &Path,
    system_dir: &Path,
    args: &[&str],
    action: &str,
) -> Result<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
    command
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir)
        .arg("package")
        .args(args);
    let output = command
        .output()
        .with_context(|| format!("running aos package {action}"))?;
    if !output.status.success() {
        bail!(
            "aos package {action} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "JSON aos package {action} should keep stderr clean:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing aos package {action} JSON from stdout"))
}

/// Spawn `apr` against an isolated `HOME`, with a committer identity in the
/// environment: registry commits refuse to run without one.
fn apr_command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apr"));
    cmd.env("HOME", home)
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
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

struct StaticHttpServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl StaticHttpServer {
    async fn spawn(root: PathBuf) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("binding static fixture HTTP server")?;
        let addr = listener.local_addr().context("reading listener address")?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let root = root.clone();
                tokio::spawn(async move {
                    let _ = serve_one(stream, root).await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    fn base_url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

impl Drop for StaticHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_one(mut stream: TcpStream, root: PathBuf) -> Result<()> {
    // Read until the end of the request headers. A single `read` can return a
    // partial request line under concurrent load (TCP segmentation), which
    // would truncate the path and 404 a valid object.
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.context("reading request")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf);
    let Some(line) = request.lines().next() else {
        return Ok(());
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    if method != "GET" && method != "HEAD" {
        write_response(&mut stream, 405, "Method Not Allowed", b"").await?;
        return Ok(());
    }

    let path = safe_path(&root, target)?;
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        write_response(&mut stream, 404, "Not Found", b"").await?;
        return Ok(());
    };
    if metadata.is_dir() {
        write_response(&mut stream, 403, "Forbidden", b"").await?;
        return Ok(());
    }

    let body = if method == "HEAD" {
        Vec::new()
    } else {
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("reading {}", path.display()))?
    };
    let length = if method == "HEAD" {
        metadata.len() as usize
    } else {
        body.len()
    };
    write_response_with_length(&mut stream, 200, "OK", length, &body).await?;
    Ok(())
}

fn safe_path(root: &Path, target: &str) -> Result<PathBuf> {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target);
    let mut out = root.to_path_buf();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." || component.contains('\\') {
            bail!("unsafe request path {target}");
        }
        out.push(component);
    }
    Ok(out)
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()> {
    write_response_with_length(stream, status, reason, body.len(), body).await
}

async fn write_response_with_length(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    length: usize,
    body: &[u8],
) -> Result<()> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .context("writing response headers")?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .context("writing response body")?;
    }
    Ok(())
}
