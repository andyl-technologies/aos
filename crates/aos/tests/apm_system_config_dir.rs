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

fn run_apr(home: &Path, system_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .env("APM_SYSTEM_CONFIG_DIR", system_dir)
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
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}
