use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[path = "support/git_ssh.rs"]
mod git_ssh;

const REAL_NIX_CACHE_TEST_ENV: &str = "AOS_PACKAGE_TEST_REAL_NIX_CACHE";

#[test]
fn apr_cache_generate_cli_uploads_static_cache() -> Result<()> {
    if std::env::var_os(REAL_NIX_CACHE_TEST_ENV).is_none() {
        eprintln!(
            "skipping apr cache CLI e2e: set {REAL_NIX_CACHE_TEST_ENV}=1 to run real nix-store fixture"
        );
        return Ok(());
    }

    let Some(store_path) = tiny_store_path_fixture()? else {
        eprintln!("skipping apr cache CLI e2e: nix or nix-store is unavailable");
        return Ok(());
    };

    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let registry_name = "cli-cache";
    let registry_dir = home
        .join(".local")
        .join("share")
        .join("apm")
        .join("registries")
        .join(registry_name);
    let config_dir = home.join(".config").join("apm").join("registries.d");
    let output_dir = tmp.path().join("cache-output");
    let upload_dir = tmp.path().join("cache-upload");

    fs::create_dir_all(registry_dir.join("packages/f"))?;
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join(format!("{registry_name}.toml")),
        format!(
            r#"[registry]
name = "{registry_name}"
url = "file://{}"
"#,
            registry_dir.display(),
        ),
    )?;
    fs::write(
        registry_dir.join("registry.toml"),
        format!(
            r#"[registry]
name = "{registry_name}"
"#,
        ),
    )?;
    fs::write(
        registry_dir.join("packages/f/fixture.toml"),
        package_toml(&store_path),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .args(["cache", "generate", "--registry", registry_name])
        .arg("--output")
        .arg(&output_dir)
        .arg("--upload-url")
        .arg(format!("file://{}", upload_dir.display()))
        .args(["--priority", "37"])
        .args([
            "--token",
            "token",
            "--view",
            "ops",
            "--http-user",
            "cache-user",
            "--http-password",
            "cache-pass",
            "--header",
            "X-Test: yes",
            "--s3-region",
            "us-west-2",
            "--s3-profile",
            "prod",
            "--s3-endpoint",
            "https://minio.example",
            "--ssh-key",
            "/tmp/aos-test-key",
            "--ssh-password",
            "ssh-pass",
            "--ssh-ask-pass",
        ])
        .output()
        .context("running apr cache generate")?;
    if !output.status.success() {
        bail!(
            "apr cache generate failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let cache_info = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 37\n";
    assert_eq!(
        fs::read_to_string(output_dir.join("nix-cache-info"))?,
        cache_info,
    );
    assert_eq!(
        fs::read_to_string(upload_dir.join("nix-cache-info"))?,
        cache_info,
    );

    let narinfo_path = only_narinfo(&output_dir)?;
    let uploaded_narinfo_path = upload_dir.join(narinfo_path.file_name().unwrap());
    assert_eq!(
        fs::read_to_string(&uploaded_narinfo_path)?,
        fs::read_to_string(&narinfo_path)?,
    );

    let nar_path = only_file_in(&output_dir.join("nar"))?;
    let uploaded_nar_path = upload_dir.join("nar").join(nar_path.file_name().unwrap());
    assert_eq!(fs::read(&uploaded_nar_path)?, fs::read(&nar_path)?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_cache_generate_cli_supports_apm_install_upgrade_and_execution() -> Result<()> {
    if std::env::var_os(REAL_NIX_CACHE_TEST_ENV).is_none() {
        eprintln!(
            "skipping apm install static-cache e2e: set {REAL_NIX_CACHE_TEST_ENV}=1 to run real nix-store fixture"
        );
        return Ok(());
    }

    if command_missing("nix") || command_missing("nix-store") {
        eprintln!("skipping apm install static-cache e2e: nix or nix-store is unavailable");
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    let consumer_aos_root = tmp.path().join("consumer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    prepare_aos_root(&consumer_aos_root)?;
    let Some(store_path_v1) =
        executable_store_path_fixture(tmp.path(), &producer_aos_root, "1.0.0")?
    else {
        eprintln!("skipping apm install static-cache e2e: nix or nix-store is unavailable");
        return Ok(());
    };

    let maintainer_home = tmp.path().join("maintainer-home");
    let consumer_home = tmp.path().join("consumer-home");
    let profile_root = tmp.path().join("profiles");
    let registry_name = "cli-install-cache";
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["create", registry_name],
    )?;
    let registry_dir = registry_dir(&maintainer_home, registry_name);
    configure_fixture_git_identity(&registry_dir)?;
    fs::create_dir_all(registry_dir.join("packages/f"))?;
    fs::write(
        registry_dir.join("packages/f/fixture-tool.toml"),
        package_toml_with_name("fixture-tool", "1.0.0", &store_path_v1),
    )?;
    git_stdout(
        &registry_dir,
        &["add", "packages/f/fixture-tool.toml"],
        "staging fixture package",
    )?;
    git_stdout(
        &registry_dir,
        &["commit", "-m", "publish fixture package"],
        "committing fixture package",
    )?;

    let cache_output = tmp.path().join("cache-output");
    let cache_server = StaticHttpServer::spawn(cache_output.clone()).await?;
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "cache",
            "generate",
            "--registry",
            registry_name,
            "--output",
            cache_output.to_str().context("cache output path utf-8")?,
            "--cache-url",
            &cache_server.base_url(),
            "--priority",
            "37",
        ],
    )?;

    let release_key = maintainer_home.join(".config/apm/keys/cli-install-cache-release.key");
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["keys", "generate", "release", "--registry", registry_name],
    )?;
    let upload_dir = tmp.path().join("origin-upload");
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "release",
            "1.0.0",
            "--registry",
            registry_name,
            "--key",
            release_key.to_str().context("release key path utf-8")?,
            "--upload-url",
            &format!("file://{}", upload_dir.display()),
        ],
    )?;

    let origin_server = StaticHttpServer::spawn(upload_dir.clone()).await?;
    let added = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &[
            "--json",
            "registry",
            "add",
            &origin_server.base_url(),
            "--no-verify",
            "--name",
            registry_name,
            "--branch",
            "stable",
        ],
        "registry add",
    )?;
    assert_eq!(added["action"], "registry_add");
    assert_eq!(added["synced"], true, "{added}");
    assert_eq!(added["packages"], 1, "{added}");

    let installed = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &[
            "--json",
            "--yes",
            "install",
            "fixture-tool",
            "--registry",
            registry_name,
        ],
        "install",
    )?;
    assert_eq!(installed["action"], "install");
    assert_eq!(installed["status"], "installed", "{installed}");
    assert_eq!(installed["downloads"]["downloaded"], 1, "{installed}");
    assert_eq!(installed["downloads"]["imported"], 1, "{installed}");

    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-tool 1.0.0\n"
    );

    let listed = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "list", "--installed", "--registry", registry_name],
        "list installed",
    )?;
    let entries = listed
        .as_array()
        .context("installed package list should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["version"], "1.0.0");
    assert!(
        entries[0]["status"]
            .as_str()
            .is_some_and(|status| status.contains("installed")),
        "{listed}",
    );

    let Some(store_path_v2) =
        executable_store_path_fixture(tmp.path(), &producer_aos_root, "2.0.0")?
    else {
        eprintln!("skipping apm install static-cache e2e: nix or nix-store is unavailable");
        return Ok(());
    };
    fs::write(
        registry_dir.join("packages/f/fixture-tool.toml"),
        package_toml_with_name("fixture-tool", "2.0.0", &store_path_v2),
    )?;
    git_stdout(
        &registry_dir,
        &["add", "packages/f/fixture-tool.toml"],
        "staging upgraded fixture package",
    )?;
    git_stdout(
        &registry_dir,
        &["commit", "-m", "publish upgraded fixture package"],
        "committing upgraded fixture package",
    )?;
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "cache",
            "generate",
            "--registry",
            registry_name,
            "--output",
            cache_output.to_str().context("cache output path utf-8")?,
            "--cache-url",
            &cache_server.base_url(),
            "--priority",
            "37",
        ],
    )?;
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "release",
            "2.0.0",
            "--registry",
            registry_name,
            "--key",
            release_key.to_str().context("release key path utf-8")?,
            "--upload-url",
            &format!("file://{}", upload_dir.display()),
        ],
    )?;

    let updated = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "update", "--registry", registry_name],
        "update upgraded origin",
    )?;
    assert_eq!(updated["action"], "update");
    assert_eq!(updated["registry"], registry_name);
    assert_eq!(updated["updated"], 1, "{updated}");

    let held = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "hold", "fixture-tool"],
        "hold before upgrade",
    )?;
    assert_eq!(held["action"], "hold");
    assert_eq!(held["status"], "held", "{held}");
    assert_eq!(held["package"], "fixture-tool");
    assert_eq!(held["version"], "1.0.0");
    assert_eq!(held["held"], true);

    let held_back = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "--yes", "upgrade", "fixture-tool"],
        "upgrade while held",
    )?;
    assert_eq!(held_back["action"], "upgrade");
    assert_eq!(held_back["status"], "held_back", "{held_back}");
    assert_eq!(held_back["upgraded"], 0, "{held_back}");
    assert_eq!(held_back["downloads"]["downloaded"], 0, "{held_back}");
    assert_eq!(held_back["downloads"]["imported"], 0, "{held_back}");
    assert_eq!(held_back["held_back"][0]["name"], "fixture-tool");
    assert_eq!(held_back["held_back"][0]["old_version"], "1.0.0");
    assert_eq!(held_back["held_back"][0]["new_version"], "2.0.0");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-tool 1.0.0\n"
    );

    let unheld = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "unhold", "fixture-tool"],
        "unhold before upgrade",
    )?;
    assert_eq!(unheld["action"], "unhold");
    assert_eq!(unheld["status"], "unheld", "{unheld}");
    assert_eq!(unheld["package"], "fixture-tool");
    assert_eq!(unheld["version"], "1.0.0");
    assert_eq!(unheld["held"], false);

    let upgraded = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "--yes", "upgrade", "fixture-tool"],
        "upgrade",
    )?;
    assert_eq!(upgraded["action"], "upgrade");
    assert_eq!(upgraded["status"], "upgraded", "{upgraded}");
    assert_eq!(upgraded["upgraded"], 1, "{upgraded}");
    assert_eq!(upgraded["downloads"]["downloaded"], 1, "{upgraded}");
    assert_eq!(upgraded["downloads"]["imported"], 1, "{upgraded}");
    assert_eq!(upgraded["upgrades"][0]["name"], "fixture-tool");
    assert_eq!(upgraded["upgrades"][0]["old_version"], "1.0.0");
    assert_eq!(upgraded["upgrades"][0]["new_version"], "2.0.0");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-tool 2.0.0\n"
    );

    let listed = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "list", "--installed", "--registry", registry_name],
        "list installed after upgrade",
    )?;
    let entries = listed
        .as_array()
        .context("upgraded package list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    assert_eq!(entries[0]["name"], "fixture-tool");
    assert_eq!(entries[0]["version"], "2.0.0");
    assert!(
        entries[0]["status"]
            .as_str()
            .is_some_and(|status| status.contains("installed")),
        "{listed}",
    );

    Ok(())
}

fn only_narinfo(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let narinfos = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("narinfo"))
        .collect::<Vec<_>>();
    if narinfos.len() != 1 {
        bail!(
            "expected one narinfo in {}, found {}",
            dir.display(),
            narinfos.len()
        );
    }
    Ok(narinfos[0].clone())
}

fn only_file_in(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let files = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if files.len() != 1 {
        bail!(
            "expected one file in {}, found {}",
            dir.display(),
            files.len()
        );
    }
    Ok(files[0].clone())
}

fn tiny_store_path_fixture() -> Result<Option<String>> {
    if command_missing("nix") || command_missing("nix-store") {
        return Ok(None);
    }

    let tmp = tempfile::Builder::new()
        .prefix("aos-cache-cli-fixture-")
        .tempfile_in("/private/tmp")?;
    fs::write(tmp.path(), b"aos apr cache cli fixture\n")?;
    let output = Command::new("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(tmp.path())
        .output()
        .context("running nix-store --add-fixed")?;
    if !output.status.success() {
        eprintln!(
            "skipping apr cache CLI e2e: nix-store --add-fixed failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn package_toml(store_path: &str) -> String {
    package_toml_with_name("fixture", "1.0.0", store_path)
}

fn package_toml_with_name(name: &str, version: &str, store_path: &str) -> String {
    let platform = current_platform();
    let mut toml = format!(
        r#"[package]
name = "{name}"
description = "Static cache fixture"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "{version}"

{}
"#,
        fixture_platform_toml("x86_64-linux", store_path),
    );
    if platform != "x86_64-linux" {
        toml.push('\n');
        toml.push_str(&fixture_platform_toml(&platform, store_path));
    }
    toml
}

fn fixture_platform_toml(platform: &str, store_path: &str) -> String {
    format!(
        r#"[versions.platforms.{platform}]
store_path = "{store_path}"
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

fn registry_dir(home: &Path, name: &str) -> PathBuf {
    home.join(".local/share/apm/registries").join(name)
}

fn executable_store_path_fixture(
    root: &Path,
    aos_root: &Path,
    version: &str,
) -> Result<Option<String>> {
    if command_missing("nix") || command_missing("nix-store") {
        return Ok(None);
    }

    let source = root.join(format!("fixture-tool-{version}"));
    fs::create_dir_all(source.join("bin"))?;
    let script = source.join("bin/fixture-tool");
    fs::write(&script, format!("printf 'fixture-tool {version}\\n'\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
    }

    let output = Command::new("nix-store")
        .envs(nix_command_env(aos_root))
        .args(["--add"])
        .arg(&source)
        .output()
        .context("running nix-store --add")?;
    if !output.status.success() {
        eprintln!(
            "skipping apm install static-cache e2e: nix-store --add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn prepare_aos_root(aos_root: &Path) -> Result<()> {
    fs::create_dir_all(aos_root.join("store"))?;
    fs::create_dir_all(aos_root.join("var/nix/log/nix"))?;
    initialize_nix_store(aos_root)?;
    Ok(())
}

fn nix_command_env(aos_root: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("AOS_ROOT", aos_root.display().to_string()),
        (
            "NIX_STORE_DIR",
            aos_root.join("store").display().to_string(),
        ),
        (
            "NIX_STATE_DIR",
            aos_root.join("var/nix").display().to_string(),
        ),
        (
            "NIX_LOG_DIR",
            aos_root.join("var/nix/log/nix").display().to_string(),
        ),
    ]
}

fn initialize_nix_store(aos_root: &Path) -> Result<()> {
    let output = Command::new("nix-store")
        .envs(nix_command_env(aos_root))
        .arg("--init")
        .output()
        .context("running nix-store --init")?;
    if !output.status.success() {
        bail!(
            "nix-store --init failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

fn run_profile_tool(profile_root: &Path, command: &str) -> Result<String> {
    let profile_bin = profile_root
        .join("per-user")
        .join(std::env::var("USER").unwrap_or_else(|_| String::from("unknown")))
        .join("current/bin")
        .join(command);
    assert!(
        profile_bin.exists(),
        "installed profile executable is missing at {}",
        profile_bin.display(),
    );
    let profile_bin_dir = profile_bin
        .parent()
        .context("installed profile executable should have a parent directory")?;
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("PATH", profile_bin_dir)
        .output()
        .with_context(|| format!("executing {}", profile_bin.display()))?;
    if !output.status.success() {
        bail!(
            "installed fixture failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_apr_with_aos_root(home: &Path, aos_root: &Path, args: &[&str]) -> Result<String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apr"));
    command
        .env("HOME", home)
        .envs(nix_command_env(aos_root))
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com")
        .args(args);
    git_ssh::apply_git_ssh_program_env(&mut command);
    let output = command
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

fn run_aos_package_json_with_env(
    home: &Path,
    aos_root: &Path,
    profile_root: &Path,
    args: &[&str],
    action: &str,
) -> Result<Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_aos"))
        .env("HOME", home)
        .envs(nix_command_env(aos_root))
        .env("AOS_PROFILE_ROOT", profile_root)
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

fn output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn command_missing(command: &str) -> bool {
    matches!(
        Command::new(command).arg("--version").output(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
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
