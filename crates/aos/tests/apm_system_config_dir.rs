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
fn system_config_dir_override_supports_apm_system_registry_add() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let system_dir = tmp.path().join("etc-apm");
    let origin = tmp.path().join("origin.git");
    fs::create_dir_all(&origin)?;

    let url = format!("file://{}", origin.display());
    let system_config = system_dir.join("registries.d/sysreg.toml");
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
        system_config.to_string_lossy().to_string(),
        "registry --system add should write the redirected system config"
    );

    let config = fs::read_to_string(&system_config)?;
    assert!(config.contains("name = \"sysreg\""), "{config}");
    assert!(config.contains(&format!("url = \"{url}\"")), "{config}");
    assert!(config.contains("priority = 701"), "{config}");
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "registry --system add should not create a user config shadow file"
    );

    let registries = run_aos_package(&home, &system_dir, &["registry", "list"])?;
    assert!(
        registries.contains("sysreg"),
        "user-scope registry list did not see redirected system registry:\n{registries}"
    );

    Ok(())
}

#[test]
fn system_config_dir_override_supports_apm_registry_lifecycle() -> Result<()> {
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

    let registries = run_aos_package(&home, &system_dir, &["registry", "list"])?;
    assert!(
        registries.contains("sysreg"),
        "aos package registry list did not see redirected system registry:\n{registries}"
    );

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
        system_config.to_string_lossy().to_string(),
        "registry disable should rewrite the effective redirected system config"
    );
    let config = fs::read_to_string(&system_config)?;
    assert!(config.contains("enabled = false"), "{config}");
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "registry disable should not create a user config shadow file"
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
        system_config.to_string_lossy().to_string(),
        "registry enable should rewrite the effective redirected system config"
    );
    let config = fs::read_to_string(&system_config)?;
    assert!(config.contains("enabled = true"), "{config}");
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "registry enable should not create a user config shadow file"
    );

    let output = run_aos_package_output(
        &home,
        &system_dir,
        &["--json", "registry", "remove", "sysreg", "--keep-local"],
    )?;
    if !output.status.success() {
        bail!(
            "aos package registry remove sysreg failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .context("parsing registry remove JSON from stdout")?;
    assert_eq!(json["action"], "registry_remove");
    assert_eq!(json["status"], "removed");
    assert_eq!(json["registry"], "sysreg");
    assert_eq!(json["keep_local"], true);
    assert_eq!(
        json["config"],
        system_config.to_string_lossy().to_string(),
        "registry remove should delete the effective redirected system config"
    );
    assert_eq!(json["config_removed"], true);
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "JSON registry remove should keep stderr clean:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !system_config.exists(),
        "registry remove left redirected system config behind at {}",
        system_config.display()
    );
    assert!(
        !home.join(".config/apm/registries.d/sysreg.toml").exists(),
        "registry remove should not create a user config shadow file"
    );

    let registries = run_aos_package(&home, &system_dir, &["registry", "list"])?;
    assert!(
        !registries.contains("sysreg"),
        "removed redirected system registry is still listed:\n{registries}"
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
        .with_context(|| format!("running aos package {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "aos package {} failed:\nstdout:\n{}\nstderr:\n{}",
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
        .with_context(|| format!("running aos package registry {action}"))?;
    if !output.status.success() {
        bail!(
            "aos package registry {action} failed:\nstdout:\n{}\nstderr:\n{}",
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
    command
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir);
    command.arg("package");
    command.args(args);
    command.output().context("running aos package")
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
        .args(args)
        .output()
        .context("running apr")
}
