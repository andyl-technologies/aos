//! End-to-end coverage for `apr origin config` and the persisted
//! upload-default fallback used by `apr origin upload`.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
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
            "--upload-url",
            &upload_url,
        ],
    )?;
    assert!(
        release.contains("Released origin-default-reg 1.0.0"),
        "{release}"
    );
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
    let package_dir = registry.join("packages/f");
    fs::create_dir_all(&package_dir)?;
    fs::write(
        package_dir.join("fixture-tool.toml"),
        fixture_package_toml("fixture-tool", "1.0.0"),
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

fn git_stdout(cwd: &Path, args: &[&str], context: &str) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
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
    let output = Command::new(env!("CARGO_BIN_EXE_aos"))
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir)
        .arg("package")
        .args(args)
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
    let mut buf = vec![0_u8; 8192];
    let n = stream.read(&mut buf).await.context("reading request")?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
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
