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
