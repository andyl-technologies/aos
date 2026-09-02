//! End-to-end coverage for the `APM_SYSTEM_CONFIG_DIR` environment variable.
//!
//! The variable redirects the system configuration root (default `/etc/apm`)
//! so that `apm`/`apr` can be exercised against a writable fixture tree on
//! non-AOS hosts. Both derived paths must follow it: `trusted-keys.d`
//! (trusted key lookups) and `registries.d` (registry configuration).

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_package::sshkey::Ed25519Keypair;
use serde_json::Value;

#[test]
fn system_config_dir_override_redirects_trusted_keys_and_registries() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");

    // Trusted keys placed under the redirected system root are visible to
    // user-scope lookups (the system trusted-keys.d is the user scope's
    // read-only fallback directory).
    let trust_dir = system_dir.join("trusted-keys.d");
    fs::create_dir_all(&trust_dir)?;
    fs::write(trust_dir.join("core.pub"), "core:Ed25519:YWJjZA==\n")?;

    let list = run_apr(&home, &system_dir, &["trust", "list", "core"])?;
    assert!(
        list.contains("core: Ed25519"),
        "trusted key under redirected system dir not listed:\n{list}"
    );

    // A registry config placed under the redirected system root is picked up
    // by registry discovery (the system registries.d is merged into the
    // user-scope view).
    let registries_dir = system_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)?;
    fs::write(
        registries_dir.join("sysreg.toml"),
        "[registry]\nname = \"sysreg\"\nurl = \"https://registry.example/sysreg\"\n",
    )?;

    let registries = run_apr(&home, &system_dir, &["list"])?;
    assert!(
        registries.contains("sysreg"),
        "registry under redirected system dir not listed:\n{registries}"
    );

    // Without the override the same fixtures must be invisible (the default
    // /etc/apm does not contain them).
    let unredirected = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .env_remove("APM_SYSTEM_CONFIG_DIR")
        .args(["list"])
        .output()
        .context("running apr list without the override")?;
    let stdout = String::from_utf8_lossy(&unredirected.stdout);
    assert!(
        !stdout.contains("sysreg"),
        "fixture registry leaked without the override:\n{stdout}"
    );

    Ok(())
}

#[test]
fn system_config_dir_override_masks_system_trust_anchor_on_user_remove() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let system_trust_dir = system_dir.join("trusted-keys.d");
    let user_key = home.join(".config/apm/trusted-keys.d/core.pub");
    let system_key = system_trust_dir.join("core.pub");
    let key_line = "core:Ed25519:YWJjZA==";
    fs::create_dir_all(&system_trust_dir)?;
    fs::write(&system_key, format!("{key_line}\n"))?;

    let listed = run_apr_json(
        &home,
        &system_dir,
        &["--json", "trust", "list", "core"],
        "trust list",
    )?;
    let entries = listed
        .as_array()
        .context("trust list JSON should be an array")?;
    assert_eq!(entries.len(), 1, "{listed}");
    let keys = entries[0]["keys"]
        .as_array()
        .context("trust list entry should contain a keys array")?;
    assert_eq!(keys.len(), 1, "{listed}");
    assert_eq!(keys[0]["source"], "PreInstalled");

    let removed = run_apr_json(
        &home,
        &system_dir,
        &["--json", "trust", "remove", "core"],
        "trust remove",
    )?;
    assert_eq!(removed["action"], "trust_remove");
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["registry"], "core");
    assert_eq!(removed["removed"], true);
    assert_eq!(
        fs::read_to_string(&system_key)?,
        format!("{key_line}\n"),
        "user-scope trust remove should not delete the system trust anchor"
    );
    assert_eq!(
        fs::read_to_string(&user_key)?,
        format!("# revoked: {key_line}\n"),
        "user-scope trust remove should mask the system anchor from the user layer"
    );

    let listed = run_apr_json(
        &home,
        &system_dir,
        &["--json", "trust", "list", "core"],
        "trust list",
    )?;
    let entries = listed
        .as_array()
        .context("trust list JSON should be an array")?;
    let keys = entries[0]["keys"]
        .as_array()
        .context("trust list entry should contain a keys array")?;
    assert!(
        keys.is_empty(),
        "masked system trust anchor should not remain visible: {listed}"
    );

    let pinned = run_apr_json(
        &home,
        &system_dir,
        &["--json", "trust", "pin", "core", key_line],
        "trust pin",
    )?;
    assert_eq!(pinned["action"], "trust_pin");
    assert_eq!(pinned["status"], "pinned");
    assert_eq!(pinned["source"], "Tofu");
    assert_eq!(
        fs::read_to_string(&user_key)?,
        format!("{key_line}\n"),
        "pinning the same key explicitly should drop the user revocation"
    );
    assert_eq!(
        fs::read_to_string(&system_key)?,
        format!("{key_line}\n"),
        "trust pin should also leave the system trust anchor untouched"
    );

    let listed = run_apr_json(
        &home,
        &system_dir,
        &["--json", "trust", "list", "core"],
        "trust list",
    )?;
    let entries = listed
        .as_array()
        .context("trust list JSON should be an array")?;
    let keys = entries[0]["keys"]
        .as_array()
        .context("trust list entry should contain a keys array")?;
    assert_eq!(keys.len(), 1, "{listed}");
    assert_eq!(keys[0]["source"], "Tofu");

    Ok(())
}

#[test]
fn system_config_dir_override_supports_apr_maintainer_config_lifecycle() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let registries_dir = system_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)?;

    let system_config = registries_dir.join("sysreg.toml");
    fs::write(
        &system_config,
        "[registry]\nname = \"sysreg\"\nurl = \"https://registry.example/sysreg\"\n",
    )?;

    let upload_dir = tmp.path().join("upload");
    let upload_url = format!("file://{}", upload_dir.display());
    let origin_config = run_apr_json(
        &home,
        &system_dir,
        &[
            "--json",
            "origin",
            "config",
            "--registry",
            "sysreg",
            "--upload-url",
            upload_url.as_str(),
        ],
        "origin config",
    )?;
    assert_eq!(origin_config["action"], "origin_config");
    assert_eq!(origin_config["registry"], "sysreg");
    assert_eq!(
        origin_config["config"],
        system_config.to_string_lossy().to_string(),
        "apr origin config should rewrite the effective redirected system config"
    );
    assert_eq!(origin_config["upload_auth"]["upload_urls"][0], upload_url);
    let config = fs::read_to_string(&system_config)?;
    assert!(config.contains("[registry.upload_auth]"), "{config}");
    assert!(
        config.contains(&format!("upload_urls = [\"{upload_url}\"]")),
        "{config}"
    );
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "apr origin config should not create a user config shadow file"
    );

    let key = run_apr_json(
        &home,
        &system_dir,
        &[
            "--json",
            "keys",
            "generate",
            "release",
            "--registry",
            "sysreg",
        ],
        "keys generate",
    )?;
    assert_eq!(key["action"], "keys_generate");
    assert_eq!(key["status"], "generated");
    assert_eq!(key["registry"], "sysreg");
    assert_eq!(key["id"], "release");
    assert_eq!(key["configured"], true);
    assert_eq!(
        key["config"],
        system_config.to_string_lossy().to_string(),
        "apr keys generate should record key-id resolution in the redirected system config"
    );
    let private_key = home.join(".config/apm/keys/sysreg-release.key");
    assert!(
        private_key.exists(),
        "apr keys generate should write the private key under user config at {}",
        private_key.display()
    );
    let config = fs::read_to_string(&system_config)?;
    assert!(config.contains("[registry.signing_keys]"), "{config}");
    assert!(
        config.contains(&format!("\"release\" = \"{}\"", private_key.display())),
        "{config}"
    );
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "apr keys generate should not create a user config shadow file"
    );

    let external_key = Ed25519Keypair::from_seed([51_u8; 32]);
    let external_key_path = home.join("external-release.key");
    fs::write(
        &external_key_path,
        external_key.to_openssh_private_key("external-release"),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&external_key_path, fs::Permissions::from_mode(0o600))?;
    }
    let registered = run_apr_json(
        &home,
        &system_dir,
        &[
            "--json",
            "keys",
            "register",
            "external",
            "--registry",
            "sysreg",
            "--key",
            external_key_path
                .to_str()
                .context("external key path must be UTF-8")?,
        ],
        "keys register",
    )?;
    assert_eq!(registered["action"], "keys_register");
    assert_eq!(registered["status"], "registered");
    assert_eq!(registered["registry"], "sysreg");
    assert_eq!(registered["id"], "external");
    assert_eq!(registered["source"], "path");
    assert_eq!(registered["configured"], true);
    assert_eq!(
        registered["config"],
        system_config.to_string_lossy().to_string(),
        "apr keys register should record key-id resolution in the redirected system config"
    );
    assert_eq!(
        registered["public_key"],
        external_key.trust_key_line("sysreg")
    );
    let config = fs::read_to_string(&system_config)?;
    assert!(
        config.contains(&format!(
            "\"external\" = \"{}\"",
            external_key_path.display()
        )),
        "{config}"
    );
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "apr keys register should not create a user config shadow file"
    );

    Ok(())
}

#[test]
fn system_config_dir_override_prefers_user_shadow_for_registry_mutations() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let system_config = system_dir.join("registries.d/shadow.toml");
    let user_config = home.join(".config/apm/registries.d/shadow.toml");

    fs::create_dir_all(system_config.parent().context("system config parent")?)?;
    fs::write(
        &system_config,
        "[registry]\nname = \"shadow\"\nurl = \"https://registry.example/system\"\npriority = 100\n",
    )?;
    fs::create_dir_all(user_config.parent().context("user config parent")?)?;
    fs::write(
        &user_config,
        "[registry]\nname = \"shadow\"\nurl = \"https://registry.example/user\"\npriority = 900\n",
    )?;

    let upload_dir = tmp.path().join("shadow-upload");
    let upload_url = format!("file://{}", upload_dir.display());
    let origin_config = run_apr_json(
        &home,
        &system_dir,
        &[
            "--json",
            "origin",
            "config",
            "--registry",
            "shadow",
            "--upload-url",
            upload_url.as_str(),
        ],
        "origin config",
    )?;
    assert_eq!(origin_config["action"], "origin_config");
    assert_eq!(
        origin_config["config"],
        user_config.to_string_lossy().to_string(),
        "apr origin config should mutate the user config that shadows system config"
    );
    let user = fs::read_to_string(&user_config)?;
    let system = fs::read_to_string(&system_config)?;
    assert!(user.contains("[registry.upload_auth]"), "{user}");
    assert!(
        user.contains(&format!("upload_urls = [\"{upload_url}\"]")),
        "{user}"
    );
    assert!(
        !system.contains("[registry.upload_auth]"),
        "system fallback config should stay untouched when user config shadows it:\n{system}"
    );

    let disabled = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "registry", "disable", "shadow"],
        "disable",
    )?;
    assert_eq!(disabled["action"], "registry_disable");
    assert_eq!(
        disabled["config"],
        user_config.to_string_lossy().to_string(),
        "registry disable should mutate the user config that shadows system config"
    );
    let user = fs::read_to_string(&user_config)?;
    let system = fs::read_to_string(&system_config)?;
    assert!(user.contains("enabled = false"), "{user}");
    assert!(
        !system.contains("enabled = false"),
        "system fallback config should stay enabled when user config shadows it:\n{system}"
    );

    Ok(())
}

#[test]
fn read_only_system_registry_can_be_toggled_with_user_override() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let system_config = system_dir.join("registries.d/readonly.toml");
    let user_config = home.join(".config/apm/registries.d/readonly.toml");

    fs::create_dir_all(system_config.parent().context("system config parent")?)?;
    fs::write(
        &system_config,
        "[registry]\nname = \"readonly\"\nurl = \"https://registry.example/readonly\"\npriority = 500\n",
    )?;
    let mut perms = fs::metadata(&system_config)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&system_config, perms)?;

    let disabled = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "registry", "disable", "readonly"],
        "disable",
    )?;
    assert_eq!(disabled["action"], "registry_disable");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["registry"], "readonly");
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["previous_enabled"], true);
    assert_eq!(
        disabled["config"],
        user_config.to_string_lossy().to_string(),
        "registry disable should create a user override when the system config is read-only"
    );
    let user = fs::read_to_string(&user_config)?;
    let system = fs::read_to_string(&system_config)?;
    assert!(user.contains("enabled = false"), "{user}");
    // The overlay is a minimal delta: url/priority keep inheriting from the
    // seed rather than being copied into the writable layer.
    assert!(
        !user.contains("url ="),
        "disable overlay should not copy the seed url:\n{user}"
    );
    assert!(
        !system.contains("enabled = false"),
        "read-only system config should stay untouched by user disable:\n{system}"
    );

    let enabled = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "registry", "enable", "readonly"],
        "enable",
    )?;
    assert_eq!(enabled["action"], "registry_enable");
    assert_eq!(enabled["status"], "enabled");
    assert_eq!(enabled["registry"], "readonly");
    assert_eq!(enabled["enabled"], true);
    assert_eq!(enabled["previous_enabled"], false);
    assert_eq!(
        enabled["config"],
        user_config.to_string_lossy().to_string(),
        "registry enable should update the existing user override"
    );
    let user = fs::read_to_string(&user_config)?;
    let system = fs::read_to_string(&system_config)?;
    assert!(user.contains("enabled = true"), "{user}");
    assert!(
        !system.contains("enabled = true"),
        "read-only system config should stay untouched by user enable:\n{system}"
    );

    let output = run_aos_package_output(&home, &system_dir, &["registry", "remove", "readonly"])?;
    assert!(
        !output.status.success(),
        "registry remove should refuse a seed-defined registry:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("defined by a read-only seed"),
        "remove error should explain the registry is seeded and must be blanked through host.nix:\n{text}"
    );
    assert!(
        user_config.exists(),
        "failed remove should keep the user override"
    );
    assert!(
        system_config.exists(),
        "failed remove should keep the system registry config"
    );

    Ok(())
}

#[test]
fn read_only_system_registry_update_persists_state_in_user_override() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let registry = tmp.path().join("readonly-update-registry");
    if !git_supports_sha256(tmp.path())? {
        eprintln!(
            "skipping redirected system update e2e: git cannot initialize a sha256 repository"
        );
        return Ok(());
    }

    fs::create_dir_all(registry.join("packages/h"))?;
    git_ok(
        &registry,
        &["init", "--object-format=sha256"],
        "initializing registry",
    )?;
    git_ok(
        &registry,
        &["config", "user.name", "Registry Test"],
        "configuring git user",
    )?;
    git_ok(
        &registry,
        &["config", "user.email", "registry@example.com"],
        "configuring git email",
    )?;
    git_ok(
        &registry,
        &["config", "commit.gpgsign", "false"],
        "disabling fixture commit signing",
    )?;
    fs::write(
        registry.join("registry.toml"),
        "[registry]\nname = \"readonly-update\"\n",
    )?;
    fs::write(
        registry.join("packages/h/hello.toml"),
        r#"[package]
name = "hello"
description = "fixture"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/00000000000000000000000000000000-hello-1.0.0"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#,
    )?;
    git_ok(&registry, &["add", "."], "staging registry")?;
    git_ok(
        &registry,
        &["commit", "-m", "release hello"],
        "committing registry",
    )?;
    let head = git_stdout(&registry, &["rev-parse", "HEAD"], "reading registry HEAD")?;

    let system_config = system_dir.join("registries.d/readonly-update.toml");
    let user_config = home.join(".config/apm/registries.d/readonly-update.toml");
    fs::create_dir_all(system_config.parent().context("system config parent")?)?;
    fs::write(
        &system_config,
        format!(
            "[registry]\nname = \"readonly-update\"\nurl = \"file://{}\"\npriority = 500\n\n[registry.signing]\nrequired = false\n",
            registry.display()
        ),
    )?;
    let mut perms = fs::metadata(&system_config)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&system_config, perms)?;

    let updated = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "update", "--registry", "readonly-update"],
        "update",
    )?;
    assert_eq!(updated["action"], "update");
    assert_eq!(updated["updated"], 1);
    let registries = updated["registries"]
        .as_array()
        .context("update JSON should contain registries array")?;
    assert_eq!(registries.len(), 1, "{updated}");
    assert_eq!(registries[0]["registry"], "readonly-update");
    assert_eq!(registries[0]["status"], "updated");
    assert_eq!(registries[0]["commit"], head);
    assert_eq!(registries[0]["packages"], 1);

    let user = fs::read_to_string(&user_config)?;
    assert!(
        user.contains("[registry.state]"),
        "update should create a user overlay with sync state:\n{user}"
    );
    assert!(
        user.contains(&format!("last_commit = \"{head}\"")),
        "user overlay should persist the synced commit:\n{user}"
    );
    // The overlay is a minimal [registry.state] delta: url/signing keep
    // inheriting from the seed rather than being copied.
    assert!(
        !user.contains("url ="),
        "state overlay should not copy the seed url:\n{user}"
    );
    let system = fs::read_to_string(&system_config)?;
    assert!(
        !system.contains("[registry.state]"),
        "read-only system config should stay untouched by user update:\n{system}"
    );

    Ok(())
}

#[test]
fn all_registry_update_fails_after_attempting_invalid_registries() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let registries_dir = system_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)?;

    for name in ["first", "second"] {
        fs::write(
            registries_dir.join(format!("{name}.toml")),
            format!(
                "[registry]\nname = \"{name}\"\nurl = \"https://registry.invalid/{name}\"\nbranch = \"main\"\nchannel = \"stable\"\n"
            ),
        )?;
    }

    let output = run_aos_package_output(&home, &system_dir, &["--progress", "off", "update"])?;
    assert!(
        !output.status.success(),
        "an unfiltered update must fail when every registry refresh fails"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Registry 'first': invalid tracking config"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Registry 'second': invalid tracking config"),
        "{stderr}"
    );
    assert!(
        stderr.contains("failed to update 2 registry(s): first, second"),
        "{stderr}"
    );

    let json_output = run_aos_package_output(
        &home,
        &system_dir,
        &["--json", "--progress", "off", "update"],
    )?;
    assert!(!json_output.status.success());
    let documents = String::from_utf8(json_output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(
        documents.len(),
        1,
        "failed JSON updates must emit one document"
    );
    assert_eq!(
        documents[0]["error"],
        "registry error: failed to update 2 registry(s): first, second"
    );

    Ok(())
}

#[test]
fn system_config_dir_override_supports_apm_system_registry_add() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let origin = tmp.path().join("origin.git");
    fs::create_dir_all(&origin)?;

    let url = format!("file://{}", origin.display());
    // A system-scope add is a self-sufficient definition written to the
    // writable layer (/var/lib/apm/config), never the read-only /etc seed.
    let writable_config = aos_root(&system_dir).join("var/lib/apm/config/registries.d/sysreg.toml");
    let added = run_aos_package_json(
        &home,
        &system_dir,
        &[
            "--json",
            "registry",
            "--system",
            "add",
            "--no-verify",
            "--no-clone",
            url.as_str(),
            "--name",
            "sysreg",
            "--priority",
            "701",
        ],
        "add",
    )?;
    assert_eq!(added["action"], "registry_add");
    assert_eq!(added["status"], "added");
    assert_eq!(added["registry"], "sysreg");
    assert_eq!(added["name"], "sysreg");
    assert_eq!(added["url"], url);
    assert_eq!(added["priority"], 701);
    assert_eq!(added["enabled"], true);
    assert_eq!(added["tracking"], "default");
    assert_eq!(added["clone"], false);
    assert_eq!(added["synced"], false);
    assert_eq!(added["verification_disabled"], true);
    assert_eq!(
        added["config"],
        writable_config.to_string_lossy().to_string(),
        "registry --system add should write the /var writable config layer"
    );

    let config = fs::read_to_string(&writable_config)?;
    assert!(config.contains("name = \"sysreg\""), "{config}");
    assert!(config.contains(&format!("url = \"{url}\"")), "{config}");
    assert!(config.contains("priority = 701"), "{config}");
    assert!(
        !system_dir.join("registries.d/sysreg.toml").exists(),
        "registry --system add must never write the read-only /etc seed"
    );
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "registry --system add should not create a user config shadow file"
    );

    let registries = run_aos_package(&home, &system_dir, &["registry", "list"])?;
    assert!(
        registries.contains("sysreg"),
        "user-scope registry list did not see the /var system registry:\n{registries}"
    );

    Ok(())
}

#[test]
fn system_config_dir_override_supports_apm_registry_lifecycle() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let registries_dir = system_dir.join("registries.d");
    let trust_dir = system_dir.join("trusted-keys.d");
    fs::create_dir_all(&registries_dir)?;
    fs::create_dir_all(&trust_dir)?;

    let system_config = registries_dir.join("sysreg.toml");
    let system_trust_key = trust_dir.join("sysreg.pub");
    fs::write(
        &system_config,
        "[registry]\nname = \"sysreg\"\nurl = \"https://registry.example/sysreg\"\n",
    )?;
    fs::write(&system_trust_key, "sysreg:Ed25519:YWJjZA==\n")?;

    let registries = run_aos_package(&home, &system_dir, &["registry", "list"])?;
    assert!(
        registries.contains("sysreg"),
        "apm registry list did not see the seeded system registry:\n{registries}"
    );

    // disable/enable a seeded registry write a minimal overlay to the writable
    // layer (here ~/.config/apm for user scope), never the read-only seed.
    let user_overlay = home.join(".config/apm/registries.d/sysreg.toml");

    let disabled = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "registry", "disable", "sysreg"],
        "disable",
    )?;
    assert_eq!(disabled["action"], "registry_disable");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["registry"], "sysreg");
    assert_eq!(disabled["enabled"], false);
    assert_eq!(
        disabled["config"],
        user_overlay.to_string_lossy().to_string(),
        "registry disable should write the writable overlay, not the seed"
    );
    let overlay = fs::read_to_string(&user_overlay)?;
    assert!(overlay.contains("enabled = false"), "{overlay}");
    assert!(
        !overlay.contains("url ="),
        "disable overlay should be a minimal delta:\n{overlay}"
    );
    assert!(
        !fs::read_to_string(&system_config)?.contains("enabled = false"),
        "the read-only seed must stay untouched by disable",
    );

    let enabled = run_aos_package_json(
        &home,
        &system_dir,
        &["--json", "registry", "enable", "sysreg"],
        "enable",
    )?;
    assert_eq!(enabled["action"], "registry_enable");
    assert_eq!(enabled["status"], "enabled");
    assert_eq!(enabled["registry"], "sysreg");
    assert_eq!(enabled["enabled"], true);
    assert_eq!(
        enabled["config"],
        user_overlay.to_string_lossy().to_string(),
        "registry enable should update the writable overlay",
    );
    assert!(fs::read_to_string(&user_overlay)?.contains("enabled = true"));

    // A seeded registry cannot be removed by apm — the seed must be blanked via
    // signed host configuration. The command is refused and nothing on disk is deleted.
    let output = run_aos_package_output(
        &home,
        &system_dir,
        &["registry", "remove", "sysreg", "--keep-local"],
    )?;
    assert!(
        !output.status.success(),
        "registry remove should refuse a seed-defined registry:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("defined by a read-only seed"),
        "remove error should explain the registry is seeded and must be blanked through host.nix:\n{text}"
    );
    assert!(
        system_config.exists() && system_trust_key.exists(),
        "a refused remove must leave the seed and its trust key in place",
    );

    Ok(())
}

#[test]
fn user_registry_shadowing_system_registry_is_not_silently_removed() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let system_registries_dir = system_dir.join("registries.d");
    let user_registries_dir = home.join(".config/apm/registries.d");
    fs::create_dir_all(&system_registries_dir)?;
    fs::create_dir_all(&user_registries_dir)?;

    let system_config = system_registries_dir.join("sysreg.toml");
    let user_config = user_registries_dir.join("sysreg.toml");
    fs::write(
        &system_config,
        "[registry]\nname = \"sysreg\"\nurl = \"https://registry.example/system\"\npriority = 100\n",
    )?;
    fs::write(
        &user_config,
        "[registry]\nname = \"sysreg\"\nurl = \"https://registry.example/user\"\npriority = 900\n",
    )?;

    let listed = run_aos_package_json(&home, &system_dir, &["--json", "registry", "list"], "list")?;
    let registries = listed
        .as_array()
        .context("registry list JSON should be an array")?;
    assert_eq!(
        registries.len(),
        1,
        "user registry should shadow the same-name system registry: {listed}"
    );
    assert_eq!(registries[0]["name"], "sysreg");
    assert_eq!(registries[0]["url"], "https://registry.example/user");
    assert_eq!(registries[0]["priority"], 900);

    let output = run_aos_package_output(&home, &system_dir, &["registry", "remove", "sysreg"])?;
    assert!(
        !output.status.success(),
        "registry remove should reject a user shadow whose seed definition would remain:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("defined by a read-only seed"),
        "remove error should explain the seed definition would remain:\n{text}"
    );
    assert!(
        user_config.exists(),
        "failed shadowed remove should leave the user registry config in place"
    );
    assert!(
        system_config.exists(),
        "failed shadowed remove should leave the system registry config in place"
    );

    Ok(())
}

#[test]
fn relative_system_config_dir_override_is_ignored() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");

    // A relative override must be ignored in favour of the default; the
    // command still works and simply sees no fixture registries.
    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .env("APM_SYSTEM_CONFIG_DIR", "relative/apm")
        .args(["list"])
        .output()
        .context("running apr list with a relative override")?;
    if !output.status.success() {
        bail!(
            "apr list with relative override failed:\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn run_aos_package(home: &Path, system_dir: &Path, args: &[&str]) -> Result<String> {
    let output = run_aos_package_output(home, system_dir, args)
        .with_context(|| format!("running apm {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "apm {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_aos_package_json(
    home: &Path,
    system_dir: &Path,
    args: &[&str],
    action: &str,
) -> Result<Value> {
    let output = run_aos_package_output(home, system_dir, args)
        .with_context(|| format!("running apm registry {action}"))?;
    if !output.status.success() {
        bail!(
            "apm registry {action} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "JSON registry {action} should keep stderr clean:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing registry {action} JSON from stdout"))
}

fn run_aos_package_output(
    home: &Path,
    system_dir: &Path,
    args: &[&str],
) -> Result<std::process::Output> {
    let root = aos_root(system_dir);
    fs::create_dir_all(root.join("etc"))?;
    fs::write(
        root.join("etc/os-release"),
        "NAME=AOS test root\nID=aos\nAOS_MODULE_ABI=1\n",
    )?;

    let mut command = Command::new(env!("CARGO_BIN_EXE_apm"));
    command
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir)
        .env("AOS_ROOT", root);
    command.args(args);
    command.output().context("running apm")
}

/// Sandboxed `$AOS_ROOT` for a fixture, so the persistent `/var/lib/apm`
/// writable layer lands under the test's tempdir instead of the real system.
fn aos_root(system_dir: &Path) -> std::path::PathBuf {
    system_dir.parent().unwrap_or(system_dir).join("aos-root")
}

fn run_apr_json(home: &Path, system_dir: &Path, args: &[&str], action: &str) -> Result<Value> {
    let output =
        run_apr_output(home, system_dir, args).with_context(|| format!("running apr {action}"))?;
    if !output.status.success() {
        bail!(
            "apr {action} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "JSON apr {action} should keep stderr clean:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing apr {action} JSON from stdout"))
}

fn run_apr(home: &Path, system_dir: &Path, args: &[&str]) -> Result<String> {
    let output = run_apr_output(home, system_dir, args)
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "apr {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_apr_output(home: &Path, system_dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir)
        .env("AOS_ROOT", aos_root(system_dir))
        .args(args)
        .output()
        .context("running apr")
}

fn git_supports_sha256(root: &Path) -> Result<bool> {
    let probe = root.join(".sha256-probe");
    fs::create_dir_all(&probe)?;
    match Command::new("git")
        .args(["init", "--object-format=sha256"])
        .current_dir(&probe)
        .output()
    {
        Ok(output) => Ok(output.status.success()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).context("running git init --object-format=sha256"),
    }
}

fn git_ok(cwd: &Path, args: &[&str], context: &str) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("{context}: git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "{context} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

fn git_stdout(cwd: &Path, args: &[&str], context: &str) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
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
