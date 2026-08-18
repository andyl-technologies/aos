use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use aos_core::nar::cache::{
    NarCompression, StaticNarInfoInput, nar_url, render_static_narinfo,
};
use aos_core::nar::export::ExportTrailer;
use aos_package::security::parse_signing_key;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[test]
fn apr_cache_generate_cli_uploads_static_cache() -> Result<()> {
    if !nix_toolchain_available("apr cache CLI e2e") {
        return Ok(());
    }
    let Some(store_path) = tiny_store_path_fixture()? else {
        eprintln!("skipping apr cache CLI e2e: nix-store could not add the fixture");
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

    let nix_tools = nix_tool_path()?;
    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .env("PATH", &nix_tools.path)
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
    if !nix_toolchain_available("apm install static-cache e2e") {
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    let consumer_aos_root = tmp.path().join("consumer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    prepare_aos_root(&consumer_aos_root)?;
    let Some(fixture_v1) = executable_store_path_fixture(tmp.path(), &producer_aos_root, "1.0.0")?
    else {
        eprintln!("skipping apm install static-cache e2e: nix-store could not add v1 fixture");
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
        package_toml_with_name("fixture-tool", "1.0.0", &fixture_v1.tool_store_path),
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
    assert_cache_entry_count(&cache_output, 2)?;

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
            "--cache-url",
            &cache_server.base_url(),
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
    assert_eq!(installed["downloads"]["downloaded"], 2, "{installed}");
    assert_eq!(installed["downloads"]["imported"], 2, "{installed}");

    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 1.0.0\nfixture-tool 1.0.0\n"
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

    let Some(fixture_v2) = executable_store_path_fixture(tmp.path(), &producer_aos_root, "2.0.0")?
    else {
        eprintln!("skipping apm install static-cache e2e: nix-store could not add v2 fixture");
        return Ok(());
    };
    fs::write(
        registry_dir.join("packages/f/fixture-tool.toml"),
        package_toml_with_versions(
            "fixture-tool",
            &[
                ("1.0.0", fixture_v1.tool_store_path.as_str()),
                ("2.0.0", fixture_v2.tool_store_path.as_str()),
            ],
        ),
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
            "--cache-url",
            &cache_server.base_url(),
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
        "fixture-helper 1.0.0\nfixture-tool 1.0.0\n"
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
    assert_eq!(upgraded["downloads"]["downloaded"], 2, "{upgraded}");
    assert_eq!(upgraded["downloads"]["imported"], 2, "{upgraded}");
    assert_eq!(upgraded["upgrades"][0]["name"], "fixture-tool");
    assert_eq!(upgraded["upgrades"][0]["old_version"], "1.0.0");
    assert_eq!(upgraded["upgrades"][0]["new_version"], "2.0.0");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 2.0.0\nfixture-tool 2.0.0\n"
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

    let planned_rollback = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "--dry-run", "rollback", "--generation", "1"],
        "rollback dry-run after real cache upgrade",
    )?;
    assert_eq!(planned_rollback["action"], "rollback");
    assert_eq!(planned_rollback["status"], "planned", "{planned_rollback}");
    assert_eq!(planned_rollback["from_generation"], 2, "{planned_rollback}");
    assert_eq!(planned_rollback["to_generation"], 1, "{planned_rollback}");
    assert_eq!(
        planned_rollback["restored"][0]["package"]["name"],
        "fixture-tool"
    );
    assert_eq!(
        planned_rollback["restored"][0]["package"]["version"],
        "1.0.0"
    );
    assert_eq!(
        planned_rollback["removed"][0]["package"]["name"],
        "fixture-tool"
    );
    assert_eq!(
        planned_rollback["removed"][0]["package"]["version"],
        "2.0.0"
    );
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 2.0.0\nfixture-tool 2.0.0\n"
    );

    let rolled_back = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "rollback", "--generation", "1"],
        "rollback after real cache upgrade",
    )?;
    assert_eq!(rolled_back["action"], "rollback");
    assert_eq!(rolled_back["status"], "rolled_back", "{rolled_back}");
    assert_eq!(rolled_back["generation"], 1, "{rolled_back}");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 1.0.0\nfixture-tool 1.0.0\n"
    );

    let removed = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "--yes", "remove", "fixture-tool"],
        "remove after real cache rollback",
    )?;
    assert_eq!(removed["action"], "remove");
    assert_eq!(removed["status"], "removed", "{removed}");
    assert_eq!(removed["removed"], 1, "{removed}");
    assert_eq!(removed["packages"][0]["name"], "fixture-tool");
    assert!(
        !profile_bin_path(&profile_root, "fixture-tool").exists(),
        "remove should delete fixture-tool from the active profile",
    );

    let restored_upgrade = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "rollback"],
        "rollback after real cache remove",
    )?;
    assert_eq!(restored_upgrade["action"], "rollback");
    assert_eq!(
        restored_upgrade["status"], "rolled_back",
        "{restored_upgrade}"
    );
    assert_eq!(restored_upgrade["generation"], 2, "{restored_upgrade}");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 2.0.0\nfixture-tool 2.0.0\n"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_release_store_path_publishes_signed_cache_channel_and_installs() -> Result<()> {
    if !nix_toolchain_available("apr release --store-path signed cache/channel e2e") {
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    let consumer_aos_root = tmp.path().join("consumer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    prepare_aos_root(&consumer_aos_root)?;
    let Some(fixture) = executable_store_path_fixture(tmp.path(), &producer_aos_root, "1.0.0")?
    else {
        eprintln!("skipping apr release --store-path e2e: nix-store could not add release fixture");
        return Ok(());
    };

    let maintainer_home = tmp.path().join("maintainer-home");
    let consumer_home = tmp.path().join("consumer-home");
    let profile_root = tmp.path().join("profiles");
    let registry_name = "release-store-path-cache";

    let key_output = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["keys", "generate", "release", "--registry", registry_name],
    )?;
    let trust_key = extract_public_key(&key_output)?;
    let key_path = maintainer_home.join(format!(".config/apm/keys/{registry_name}-release.key"));
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "create",
            registry_name,
            "--trust-key",
            &trust_key,
            "--key",
            key_path.to_str().context("release key path utf-8")?,
        ],
    )?;

    let upload_dir = tmp.path().join("release-origin-upload");
    let cache_server = StaticHttpServer::spawn(upload_dir.clone()).await?;
    let upload_url = format!("file://{}", upload_dir.display());
    let release = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "release",
            "1.0.0",
            "--registry",
            registry_name,
            "--store-path",
            &fixture.tool_store_path,
            "--name",
            "fixture-tool",
            "--description",
            "Release store-path fixture",
            "--license",
            "MIT",
            "--maintainer",
            "registry@example.com",
            "--key",
            key_path.to_str().context("release key path utf-8")?,
            "--cache-url",
            &cache_server.base_url(),
            "--cache-priority",
            "41",
            "--channel",
            "stable",
            "--init-channel",
            "--upload-url",
            &upload_url,
        ],
    )?;
    assert!(
        release.contains("Committed: publish fixture-tool 1.0.0"),
        "{release}",
    );
    assert!(
        release.contains("Updated registry.toml [caches]"),
        "{release}",
    );
    assert!(
        release.contains("Generated static cache: 2 narinfos, 2 NARs"),
        "{release}",
    );
    assert!(
        release.contains("Initialized channel 'stable'"),
        "{release}",
    );
    assert!(
        release.contains("Released release-store-path-cache 1.0.0"),
        "{release}",
    );
    assert_cache_entry_count(&upload_dir, 2)?;

    let registry_dir = registry_dir(&maintainer_home, registry_name);
    let package_toml = fs::read_to_string(registry_dir.join("packages/f/fixture-tool.toml"))?;
    assert!(
        package_toml.contains(&format!("store_path = \"{}\"", fixture.tool_store_path)),
        "{package_toml}",
    );
    // RFC-0005: dependency edges live in the `store/` realisation graph, not
    // the package TOML (which now records only store_path/closure_size). The
    // published tool record must list the helper as a runtime dependency, and
    // the helper must have its own realisation record.
    let tool_hash = store_path_hash(&fixture.tool_store_path)?;
    let helper_hash = store_path_hash(&fixture.helper_store_path)?;
    let store_dir = registry_dir.join("store");
    let tool_record = fs::read_to_string(store_dir.join(&tool_hash[..2]).join(&tool_hash))
        .with_context(|| format!("reading published store/ record for tool {tool_hash}"))?;
    assert!(
        tool_record.contains(&format!("ia:sha256:{helper_hash}")),
        "published store/ record for the tool should record helper reference {helper_hash}:\n{tool_record}",
    );
    assert!(
        store_dir
            .join(&helper_hash[..2])
            .join(&helper_hash)
            .exists(),
        "published store/ graph should include a realisation record for the helper {helper_hash}",
    );
    assert!(
        fs::read_to_string(registry_dir.join("registry.toml"))?
            .contains(&format!("endpoint = \"{}\"", cache_server.base_url())),
        "release should commit the static cache pointer",
    );
    assert!(
        upload_dir.join("channels/stable/00").exists(),
        "uploaded signed channel is missing a partition in {}",
        upload_dir.display(),
    );

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
            "--trust-key",
            &trust_key,
            "--name",
            registry_name,
            "--channel",
            "stable",
        ],
        "verified release-store-path registry add",
    )?;
    assert_eq!(added["action"], "registry_add");
    assert_eq!(added["registry"], registry_name);
    assert_eq!(added["synced"], true, "{added}");
    assert_eq!(added["packages"], 1, "{added}");
    assert_eq!(added["signing_required"], true, "{added}");
    assert_eq!(added["trusted_key_pinned"], true, "{added}");

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
        "install release-store-path fixture",
    )?;
    assert_eq!(installed["action"], "install");
    assert_eq!(installed["status"], "installed", "{installed}");
    assert_eq!(installed["downloads"]["downloaded"], 2, "{installed}");
    assert_eq!(installed["downloads"]["imported"], 2, "{installed}");
    assert_eq!(
        run_profile_tool(&profile_root, "fixture-tool")?,
        "fixture-helper 1.0.0\nfixture-tool 1.0.0\n"
    );

    let verified = run_aos_package_json_with_env(
        &consumer_home,
        &consumer_aos_root,
        &profile_root,
        &["--json", "verify", "fixture-tool"],
        "verify release-store-path fixture",
    )?;
    assert_eq!(verified["package"], "fixture-tool");
    assert_eq!(verified["registry"], registry_name);
    assert_eq!(verified["version"], "1.0.0");
    assert_eq!(verified["verified"], true, "{verified}");

    Ok(())
}

/// All-or-nothing: a release whose cache upload fails must leave neither an
/// advertised cache-stack change nor a release tag behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_release_aborts_without_pointer_or_tag_when_upload_fails() -> Result<()> {
    if !nix_toolchain_available("apr release all-or-nothing e2e") {
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    let Some(fixture) = executable_store_path_fixture(tmp.path(), &producer_aos_root, "1.0.0")?
    else {
        eprintln!("skipping apr release all-or-nothing e2e: nix-store could not add fixture");
        return Ok(());
    };

    let maintainer_home = tmp.path().join("maintainer-home");
    let registry_name = "release-all-or-nothing";
    let key_output = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["keys", "generate", "release", "--registry", registry_name],
    )?;
    let trust_key = extract_public_key(&key_output)?;
    let key_path = maintainer_home.join(format!(".config/apm/keys/{registry_name}-release.key"));
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "create",
            registry_name,
            "--trust-key",
            &trust_key,
            "--key",
            key_path.to_str().context("release key path utf-8")?,
        ],
    )?;

    // Poison the destination: a regular file where the backend expects a
    // directory, so the cache-bytes upload fails after generation succeeds.
    let poisoned = tmp.path().join("poisoned-origin");
    fs::write(&poisoned, b"not a directory")?;
    let upload_url = format!("file://{}", poisoned.display());

    let release = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "release",
            "1.0.0",
            "--registry",
            registry_name,
            "--store-path",
            &fixture.tool_store_path,
            "--name",
            "fixture-tool",
            "--key",
            key_path.to_str().context("release key path utf-8")?,
            "--cache-url",
            "http://127.0.0.1:9/cache",
            "--upload-url",
            &upload_url,
        ],
    );
    let message = format!(
        "{:#}",
        release.expect_err("release must fail when the cache upload fails")
    );
    assert!(
        message.contains("poisoned-origin"),
        "release failure should surface the failing destination:\n{message}",
    );

    let registry_dir = registry_dir(&maintainer_home, registry_name);
    let registry_toml = fs::read_to_string(registry_dir.join("registry.toml"))?;
    assert!(
        !registry_toml.contains("[caches]"),
        "a failed release must not advertise a cache pointer:\n{registry_toml}",
    );
    let tags = git_stdout(&registry_dir, &["tag", "--list"], "listing release tags")?;
    assert!(
        !tags.lines().any(|tag| tag.trim() == "1.0.0"),
        "a failed release must not leave a 1.0.0 tag behind, found:\n{tags}",
    );

    Ok(())
}

/// A second release whose closure is already present on the destination skips
/// it entirely — no narinfo or NAR is regenerated (§7.4 root early-out).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apr_release_skips_already_published_closure() -> Result<()> {
    if !nix_toolchain_available("apr release remote-skip e2e") {
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    let Some(fixture) = executable_store_path_fixture(tmp.path(), &producer_aos_root, "1.0.0")?
    else {
        eprintln!("skipping apr release remote-skip e2e: nix-store could not add fixture");
        return Ok(());
    };

    let maintainer_home = tmp.path().join("maintainer-home");
    let registry_name = "release-remote-skip";
    let key_output = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["keys", "generate", "release", "--registry", registry_name],
    )?;
    let trust_key = extract_public_key(&key_output)?;
    let key_path = maintainer_home.join(format!(".config/apm/keys/{registry_name}-release.key"));
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "create",
            registry_name,
            "--trust-key",
            &trust_key,
            "--key",
            key_path.to_str().context("release key path utf-8")?,
        ],
    )?;
    let registry_dir = registry_dir(&maintainer_home, registry_name);
    configure_fixture_git_identity(&registry_dir)?;
    fs::create_dir_all(registry_dir.join("packages/f"))?;
    fs::write(
        registry_dir.join("packages/f/fixture-tool.toml"),
        package_toml_with_name("fixture-tool", "1.0.0", &fixture.tool_store_path),
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

    let upload_dir = tmp.path().join("origin-upload");
    let release_args = |version: &str| -> Vec<String> {
        vec![
            "release".to_string(),
            version.to_string(),
            "--registry".to_string(),
            registry_name.to_string(),
            "--key".to_string(),
            key_path.to_string_lossy().into_owned(),
            "--cache-url".to_string(),
            "http://127.0.0.1:9/cache".to_string(),
            "--upload-url".to_string(),
            format!("file://{}", upload_dir.display()),
        ]
    };

    // First release publishes the whole closure (tool + helper).
    let first = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &release_args("1.0.0")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    assert!(
        first.contains("Generated static cache: 2 narinfos, 2 NARs"),
        "first release should generate the full closure:\n{first}",
    );
    assert_cache_entry_count(&upload_dir, 2)?;

    // Re-point a new version at the same store path, then release it: the root
    // narinfo is already present, so the whole subtree is skipped.
    fs::write(
        registry_dir.join("packages/f/fixture-tool.toml"),
        package_toml_with_versions(
            "fixture-tool",
            &[
                ("1.0.0", fixture.tool_store_path.as_str()),
                ("2.0.0", fixture.tool_store_path.as_str()),
            ],
        ),
    )?;
    git_stdout(
        &registry_dir,
        &["add", "packages/f/fixture-tool.toml"],
        "staging second version",
    )?;
    git_stdout(
        &registry_dir,
        &["commit", "-m", "publish second version"],
        "committing second version",
    )?;
    let second = run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &release_args("2.0.0")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    assert!(
        second.contains("Generated static cache: 0 narinfos, 0 NARs"),
        "second release of an already-published closure should regenerate nothing:\n{second}",
    );
    assert!(
        second.contains("remote-skipped"),
        "second release should report a remote skip:\n{second}",
    );

    Ok(())
}

/// `apr origin upload --cache-dir` uploads BOTH the static cache bytes and the
/// git origin surface to the destination. This locks in the dedup that routes
/// the cache through `upload_static_cache_to_all` (no longer bundled through
/// the origin uploader). Pure file I/O — no Nix toolchain is exercised.
#[test]
fn apr_origin_upload_uploads_cache_and_git_origin() -> Result<()> {
    if !nix_toolchain_available("apr origin upload --cache-dir e2e") {
        return Ok(());
    }

    let tmp = tempfile::TempDir::new()?;
    let producer_aos_root = tmp.path().join("producer-aos-root");
    prepare_aos_root(&producer_aos_root)?;
    let maintainer_home = tmp.path().join("maintainer-home");
    let registry_name = "origin-upload-dedup";
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &["create", registry_name],
    )?;

    // Fabricate one valid content-addressed cache entry. Origin upload parses
    // staged narinfos so it cannot publish dangling or non-canonical NAR URLs.
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(cache_dir.join("nar"))?;
    fs::write(
        cache_dir.join("nix-cache-info"),
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n",
    )?;
    let nar = b"zstd-nar-bytes";
    let store_path = "/nix/store/abc123-x";
    let file_hash = format!("sha256:{:x}", Sha256::digest(nar));
    let payload_url = nar_url(store_path, &file_hash, NarCompression::Zstd)?;
    let narinfo = render_static_narinfo(
        &StaticNarInfoInput {
            store_path,
            nar_hash: "sha256:def456",
            nar_size: nar.len() as u64,
            references: &[],
            deriver: None,
            signatures: &[],
            file_hash: &file_hash,
            file_size: nar.len() as u64,
            compression: NarCompression::Zstd,
        },
        "/nix/store",
        None,
    )?;
    fs::write(cache_dir.join("abc123.narinfo"), narinfo)?;
    fs::write(cache_dir.join(&payload_url), nar)?;

    let dest = tmp.path().join("origin-dest");
    run_apr_with_aos_root(
        &maintainer_home,
        &producer_aos_root,
        &[
            "origin",
            "upload",
            "--registry",
            registry_name,
            "--cache-dir",
            cache_dir.to_str().context("cache dir utf-8")?,
            "--upload-url",
            &format!("file://{}", dest.display()),
        ],
    )?;

    // Cache surface landed.
    assert!(
        dest.join("nix-cache-info").is_file(),
        "missing nix-cache-info"
    );
    assert!(dest.join("abc123.narinfo").is_file(), "missing narinfo");
    assert!(
        dest.join(&payload_url).is_file(),
        "missing NAR under nar/",
    );
    // Git origin surface landed in the same upload.
    assert!(dest.join("HEAD").is_file(), "missing git HEAD");
    assert!(dest.join("info/refs").is_file(), "missing git info/refs");
    assert!(dest.join("objects").is_dir(), "missing git objects/");

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

fn assert_cache_entry_count(cache_dir: &Path, expected: usize) -> Result<()> {
    let narinfos = fs::read_dir(cache_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("narinfo"))
        .count();
    let nars = fs::read_dir(cache_dir.join("nar"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .count();
    assert_eq!(
        narinfos,
        expected,
        "expected {expected} narinfo(s) in {}",
        cache_dir.display(),
    );
    assert_eq!(
        nars,
        expected,
        "expected {expected} NAR(s) in {}",
        cache_dir.join("nar").display(),
    );
    Ok(())
}

fn tiny_store_path_fixture() -> Result<Option<String>> {
    let tmp = tempfile::Builder::new()
        .prefix("aos-cache-cli-fixture-")
        .tempfile()?;
    fs::write(tmp.path(), b"aos apr cache cli fixture\n")?;
    let output = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
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
    package_toml_with_versions(name, &[(version, store_path)])
}

fn package_toml_with_versions(name: &str, versions: &[(&str, &str)]) -> String {
    let platform = current_platform();
    let mut toml = format!(
        r#"[package]
name = "{name}"
description = "Static cache fixture"
license = "MIT"
maintainer = "registry@example.com"
"#,
    );
    for (version, store_path) in versions {
        toml.push_str(&format!(
            r#"
[[versions]]
version = "{version}"

{}
"#,
            fixture_platform_toml("x86_64-linux", store_path),
        ));
        if platform != "x86_64-linux" {
            toml.push('\n');
            toml.push_str(&fixture_platform_toml(&platform, store_path));
        }
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

struct ExecutableFixture {
    tool_store_path: String,
    helper_store_path: String,
}

fn executable_store_path_fixture(
    root: &Path,
    aos_root: &Path,
    version: &str,
) -> Result<Option<ExecutableFixture>> {
    let shell = find_shell()?;

    let helper = root.join(format!("fixture-helper-{version}"));
    fs::create_dir_all(helper.join("bin"))?;
    fs::create_dir_all(helper.join("share/fixture-helper"))?;
    let payload = helper.join("share/fixture-helper/payload.bin");
    fs::write(&payload, deterministic_payload(1024 * 1024))?;
    let helper_script = helper.join("bin/fixture-helper");
    fs::write(
        &helper_script,
        format!(
            "#!{}\nif [ ! -s \"{}\" ]; then\n  printf '%s\\n' 'missing helper payload' >&2\n  exit 66\nfi\nprintf 'fixture-helper {version}\\n'\n",
            shell.display(),
            payload.display(),
        ),
    )?;
    make_executable(&helper_script)?;
    let Some(helper_store_path) = add_path_to_store(aos_root, &helper, "helper")? else {
        return Ok(None);
    };

    let source = root.join(format!("fixture-tool-{version}"));
    fs::create_dir_all(source.join("bin"))?;
    let script = source.join("bin/fixture-tool");
    fs::write(
        &script,
        format!(
            "#!{}\n\"{helper_store_path}/bin/fixture-helper\"\nprintf 'fixture-tool {version}\\n'\n",
            shell.display(),
        ),
    )?;
    make_executable(&script)?;

    let Some(tool_store_path) = add_path_to_store(aos_root, &source, "tool")? else {
        return Ok(None);
    };
    register_store_references(
        aos_root,
        &tool_store_path,
        std::slice::from_ref(&helper_store_path),
    )?;
    Ok(Some(ExecutableFixture {
        tool_store_path,
        helper_store_path,
    }))
}

fn extract_public_key(output: &str) -> Result<String> {
    output
        .lines()
        .filter_map(|line| {
            let value = line.split_whitespace().last()?;
            parse_signing_key(value).ok().map(|_| value.to_string())
        })
        .next()
        .with_context(|| {
            format!("apr keys generate output did not contain a public key:\n{output}")
        })
}

fn store_path_hash(store_path: &str) -> Result<String> {
    let basename = Path::new(store_path)
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("store path should have a valid basename: {store_path}"))?;
    let (hash, _) = basename
        .split_once('-')
        .with_context(|| format!("store path basename should include a hash prefix: {basename}"))?;
    Ok(hash.to_string())
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len).map(|idx| b'a' + (idx % 26) as u8).collect()
}

fn add_path_to_store(aos_root: &Path, source: &Path, label: &str) -> Result<Option<String>> {
    let output = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
        .envs(nix_command_env(aos_root))
        .args(["--add"])
        .arg(source)
        .output()
        .with_context(|| format!("running nix-store --add for fixture {label}"))?;
    if !output.status.success() {
        eprintln!(
            "skipping apm install static-cache e2e: nix-store --add for fixture {label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn register_store_references(
    aos_root: &Path,
    store_path: &str,
    references: &[String],
) -> Result<()> {
    let dump = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
        .envs(nix_command_env(aos_root))
        .args(["--dump", store_path])
        .output()
        .with_context(|| format!("running nix-store --dump {store_path}"))?;
    if !dump.status.success() {
        bail!(
            "nix-store --dump failed for {store_path}: {}",
            String::from_utf8_lossy(&dump.stderr).trim(),
        );
    }

    let deleted = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
        .envs(nix_command_env(aos_root))
        .args(["--delete", store_path])
        .output()
        .with_context(|| format!("running nix-store --delete {store_path}"))?;
    if !deleted.status.success() {
        bail!(
            "nix-store --delete failed for {store_path}: {}",
            String::from_utf8_lossy(&deleted.stderr).trim(),
        );
    }

    let trailer = ExportTrailer::new(store_path, references.to_vec(), None);
    let mut child = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
        .envs(nix_command_env(aos_root))
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning nix-store --import")?;
    {
        let stdin = child.stdin.as_mut().context("nix-store --import stdin")?;
        trailer
            .write_import_stream(stdin, &dump.stdout)
            .context("writing referenced import stream")?;
        stdin.flush().context("flushing referenced import stream")?;
    }
    let imported = child
        .wait_with_output()
        .context("waiting for nix-store --import")?;
    if !imported.status.success() {
        bail!(
            "nix-store --import failed for {store_path}: {}",
            String::from_utf8_lossy(&imported.stderr).trim(),
        );
    }

    let refs = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
        .envs(nix_command_env(aos_root))
        .args(["-q", "--references", store_path])
        .output()
        .with_context(|| format!("running nix-store -q --references {store_path}"))?;
    if !refs.status.success() {
        bail!(
            "nix-store -q --references failed for {store_path}: {}",
            String::from_utf8_lossy(&refs.stderr).trim(),
        );
    }
    let refs_stdout = String::from_utf8_lossy(&refs.stdout);
    for reference in references {
        assert!(
            refs_stdout.lines().any(|line| line.trim() == reference),
            "registered references for {store_path} should contain {reference}:\n{refs_stdout}",
        );
    }
    Ok(())
}

fn prepare_aos_root(aos_root: &Path) -> Result<()> {
    fs::create_dir_all(nix_store_dir(aos_root))?;
    fs::create_dir_all(aos_root.join("var/nix/log/nix"))?;
    initialize_nix_store(aos_root)?;
    Ok(())
}

fn nix_command_env(aos_root: &Path) -> Vec<(&'static str, String)> {
    let store_dir = nix_store_dir(aos_root);
    vec![
        ("AOS_ROOT", aos_root.display().to_string()),
        ("AOS_NIX_STORE_DIR", store_dir.display().to_string()),
        ("NIX_STORE_DIR", store_dir.display().to_string()),
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

fn nix_store_dir(aos_root: &Path) -> PathBuf {
    aos_root
        .parent()
        .map(|parent| {
            // Resolve symlinks in the store's parent: on macOS the temp dir
            // lives under /var -> /private/var, and `nix-store` refuses a store
            // whose parent path traverses a symlink.
            std::fs::canonicalize(parent)
                .unwrap_or_else(|_| parent.to_path_buf())
                .join("shared-store")
        })
        .unwrap_or_else(|| aos_root.join("store"))
}

fn initialize_nix_store(aos_root: &Path) -> Result<()> {
    let output = nix_store_command()?
        .env_remove("LD_LIBRARY_PATH")
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
    let profile_bin = profile_bin_path(profile_root, command);
    assert!(
        profile_bin.exists(),
        "installed profile executable is missing at {}",
        profile_bin.display(),
    );
    let output = Command::new(&profile_bin)
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

fn profile_bin_path(profile_root: &Path, command: &str) -> PathBuf {
    profile_root
        .join("per-user")
        .join(std::env::var("USER").unwrap_or_else(|_| String::from("unknown")))
        .join("current/bin")
        .join(command)
}

fn run_apr_with_aos_root(home: &Path, aos_root: &Path, args: &[&str]) -> Result<String> {
    let nix_tools = nix_tool_path()?;
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
        .env("PATH", &nix_tools.path)
        .args(args);
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
    let nix_tools = nix_tool_path()?;
    let output = Command::new(env!("CARGO_BIN_EXE_aos"))
        .env("HOME", home)
        .envs(nix_command_env(aos_root))
        .env("AOS_PROFILE_ROOT", profile_root)
        .env("PATH", &nix_tools.path)
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

fn nix_toolchain_available(context: &str) -> bool {
    let nix = find_working_tool("nix", "AOS_TEST_NIX");
    let nix_store = find_working_tool("nix-store", "AOS_TEST_NIX_STORE");
    if nix.is_some() && nix_store.is_some() {
        return true;
    }

    eprintln!("skipping {context}: no working nix/nix-store toolchain is available");
    false
}

fn nix_store_command() -> Result<Command> {
    let path = find_working_tool("nix-store", "AOS_TEST_NIX_STORE")
        .context("no working nix-store found")?;
    Ok(Command::new(path))
}

struct NixToolPath {
    _tmp: tempfile::TempDir,
    path: OsString,
}

fn nix_tool_path() -> Result<NixToolPath> {
    let tmp = tempfile::Builder::new()
        .prefix("aos-tools-")
        .tempdir()
        .context("creating Nix tool wrapper directory")?;
    let shell = find_shell()?;

    for (command, override_env) in [("nix", "AOS_TEST_NIX"), ("nix-store", "AOS_TEST_NIX_STORE")] {
        let real = find_working_tool(command, override_env)
            .with_context(|| format!("no working {command} found"))?;
        let wrapper = tmp.path().join(command);
        fs::write(
            &wrapper,
            format!(
                "#!{}\nunset LD_LIBRARY_PATH\nexec \"{}\" \"$@\"\n",
                shell.display(),
                real.display(),
            ),
        )
        .with_context(|| format!("writing {}", wrapper.display()))?;
        make_executable(&wrapper)?;
    }

    let mut paths = vec![tmp.path().to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        for path in std::env::split_paths(&current) {
            push_unique_path(&mut paths, path);
        }
    }

    Ok(NixToolPath {
        _tmp: tmp,
        path: std::env::join_paths(paths).context("joining PATH with Nix wrappers first")?,
    })
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn find_working_tool(command: &str, override_env: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os(override_env) {
        candidates.push(PathBuf::from(path));
    }
    for env_var in ["AOS_HOST_PATH", "PATH"] {
        let Some(path) = std::env::var_os(env_var) else {
            continue;
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(command);
            if !candidates.iter().any(|seen| seen == &candidate) {
                candidates.push(candidate);
            }
        }
    }

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file() && tool_reports_version(candidate))
}

fn tool_reports_version(candidate: &Path) -> bool {
    Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn find_shell() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH must be set to locate sh")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("sh");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("sh not found in PATH");
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("making {} executable", path.display()))?;
    }
    Ok(())
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
