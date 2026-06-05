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

    run_apr(&home, &["trust", "remove", "core"])?;
    assert!(!key_file.exists());

    let err = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .args(["trust", "pin", "core", "other:Ed25519:YWJjZA=="])
        .output()
        .context("running apr trust pin with mismatched registry")?;
    assert!(!err.status.success());
    assert!(String::from_utf8_lossy(&err.stderr).contains("expected 'core'"));

    Ok(())
}

fn run_apr(home: &std::path::Path, args: &[&str]) -> Result<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
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
