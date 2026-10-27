#[macro_use]
#[path = "support/binaries.rs"]
mod binaries;

use std::fs;
use std::process::Command;

use anyhow::{Context, Result, bail};

#[test]
fn apr_trust_cli_pins_lists_replaces_and_removes_keys() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let trust_dir = home.join(".config").join("apm").join("trusted-keys.d");
    let key_file = trust_dir.join("core.pub");

    run_apr(&home, &["trust", "pin", "core", "core:Ed25519:YWJjZA=="])?;
    assert_eq!(fs::read_to_string(&key_file)?, "core:Ed25519:YWJjZA==\n",);

    run_apr(&home, &["trust", "pin", "core", "core:Ed25519:ZWZnaA=="])?;
    let content = fs::read_to_string(&key_file)?;
    assert!(content.contains("core:Ed25519:YWJjZA=="));
    assert!(content.contains("core:Ed25519:ZWZnaA=="));

    let list = run_apr(&home, &["trust", "list", "core"])?;
    assert!(list.contains("core: Ed25519"));

    run_apr(
        &home,
        &["trust", "pin", "core", "core:Ed25519:aGlqa2w=", "--replace"],
    )?;
    assert_eq!(fs::read_to_string(&key_file)?, "core:Ed25519:aGlqa2w=\n",);

    let output = run_apr(&home, &["trust", "remove", "core"])?;
    assert!(output.contains("Removed pinned trust keys"));
    assert_eq!(
        fs::read_to_string(&key_file)?,
        "# bootstrap disabled\n# revoked: core:Ed25519:aGlqa2w=\n"
    );

    run_apr(&home, &["trust", "pin", "core", "core:Ed25519:aGlqa2w="])?;
    assert_eq!(fs::read_to_string(&key_file)?, "core:Ed25519:aGlqa2w=\n");

    let err = Command::new(cli_binary!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .args(["trust", "pin", "core", "other:Ed25519:YWJjZA=="])
        .output()
        .context("running apr trust pin with mismatched registry")?;
    assert!(!err.status.success());
    assert!(String::from_utf8_lossy(&err.stderr).contains("expected 'core'"));

    Ok(())
}

#[test]
fn apr_trust_cli_removes_configuration_only_bootstrap_key() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let config_dir = home.join(".config").join("apm");
    let registry_dir = config_dir.join("registries.d");
    fs::create_dir_all(&registry_dir)?;
    fs::write(
        registry_dir.join("core.toml"),
        r#"[registry]
name = "core"
url = "https://registry.invalid/core"

[registry.signing]
required = true
public_key = "core:Ed25519:YWJjZA=="
"#,
    )?;

    let output = run_apr(&home, &["trust", "remove", "core"])?;
    assert!(output.contains("Removed pinned trust keys"));

    let key_file = config_dir.join("trusted-keys.d").join("core.pub");
    assert_eq!(
        fs::read_to_string(&key_file)?,
        "# bootstrap disabled\n# revoked: core:Ed25519:YWJjZA==\n"
    );

    Ok(())
}

fn run_apr(home: &std::path::Path, args: &[&str]) -> Result<String> {
    let output = Command::new(cli_binary!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
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
