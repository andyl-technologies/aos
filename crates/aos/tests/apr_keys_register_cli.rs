//! End-to-end coverage for `apr keys register`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use aos_package::sshkey::Ed25519Keypair;

#[test]
fn apr_keys_register_requires_registry_config_before_running_key_command() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    fs::create_dir_all(&home)?;

    // The key command leaves a marker file when it runs; with no
    // registries.d config the command must fail *before* the key source is
    // consulted (a real source may prompt, e.g. a secrets manager).
    let marker = home.join("key-command-ran");
    let key_command = format!("touch {} && exit 1", marker.display());
    let err = run_apr_err(
        &home,
        &[
            "keys",
            "register",
            "louis",
            "--key-command",
            &key_command,
            "--registry",
            "core",
        ],
    )?;
    let text = output_text(&err);
    assert!(text.contains("has no config"), "{text}");
    assert!(text.contains("add <url>"), "{text}");
    assert!(!marker.exists(), "key command ran despite missing config");

    Ok(())
}

#[test]
fn apr_keys_register_records_command_source_and_prints_trust_key() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let (trust_key, key_path) = write_keypair(&home, "core", [47_u8; 32], "louis")?;
    write_registry_config(&home, "core")?;

    let key_command = format!("cat {}", key_path.display());
    let output = run_apr(
        &home,
        &[
            "keys",
            "register",
            "louis",
            "--key-command",
            &key_command,
            "--registry",
            "core",
        ],
    )?;

    // The printed public key is derived from the command's output.
    assert!(output.contains(&trust_key), "{output}");

    // The command source is recorded so --key-id louis resolves.
    let config = fs::read_to_string(home.join(".config/apm/registries.d/core.toml"))?;
    assert!(config.contains("[registry.signing_keys]"), "{config}");
    assert!(
        config.contains(&format!("\"louis\" = {{ command = \"{key_command}\" }}")),
        "{config}",
    );
    // User-edited fields survive the rewrite.
    assert!(config.contains("url = \"file:///dev/null\""), "{config}");

    Ok(())
}

#[test]
fn apr_keys_register_records_path_source() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let (trust_key, key_path) = write_keypair(&home, "core", [48_u8; 32], "alice")?;
    write_registry_config(&home, "core")?;

    let output = run_apr(
        &home,
        &[
            "keys",
            "register",
            "alice",
            "--key",
            key_path.to_str().context("key path utf-8")?,
            "--registry",
            "core",
        ],
    )?;
    assert!(output.contains(&trust_key), "{output}");

    let config = fs::read_to_string(home.join(".config/apm/registries.d/core.toml"))?;
    assert!(
        config.contains(&format!("\"alice\" = \"{}\"", key_path.display())),
        "{config}",
    );

    Ok(())
}

#[test]
fn apr_keys_register_reports_failing_key_command() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    fs::create_dir_all(&home)?;
    write_registry_config(&home, "core")?;

    let err = run_apr_err(
        &home,
        &[
            "keys",
            "register",
            "louis",
            "--key-command",
            "exit 3",
            "--registry",
            "core",
        ],
    )?;
    let text = output_text(&err);
    assert!(text.contains("signing key command"), "{text}");

    // Nothing was recorded for the failed registration.
    let config = fs::read_to_string(home.join(".config/apm/registries.d/core.toml"))?;
    assert!(!config.contains("louis"), "{config}");

    Ok(())
}

#[test]
fn apr_keys_register_tolerates_key_command_trailing_newline() -> Result<()> {
    // A real secret-manager pipeline — e.g. `op item get ... | jq -r .value` —
    // appends a newline to a key that is already newline-terminated, yielding a
    // double `\n`. The strict in-process OpenSSH reader used to reject that with
    // a "pre-encapsulation boundary" error; registration must tolerate it.
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let (trust_key, key_path) = write_keypair(&home, "core", [61_u8; 32], "louis")?;
    write_registry_config(&home, "core")?;

    // `cat <key>; echo` re-emits the newline-terminated key and appends a second
    // newline — the exact byte sequence `jq -r` produces.
    let key_command = format!("cat {}; echo", key_path.display());
    let output = run_apr(
        &home,
        &[
            "keys",
            "register",
            "louis",
            "--key-command",
            &key_command,
            "--registry",
            "core",
        ],
    )?;
    assert!(output.contains(&trust_key), "{output}");

    Ok(())
}

fn write_keypair(
    home: &Path,
    registry: &str,
    seed: [u8; 32],
    name: &str,
) -> Result<(String, PathBuf)> {
    let keypair = Ed25519Keypair::from_seed(seed);
    let dir = home.join("fixture-keys");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{registry}-{name}.key"));
    fs::write(&path, keypair.to_openssh_private_key(name))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok((keypair.trust_key_line(registry), path))
}

fn write_registry_config(home: &Path, name: &str) -> Result<()> {
    let dir = home.join(".config/apm/registries.d");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join(format!("{name}.toml")),
        format!("[registry]\nname = \"{name}\"\nurl = \"file:///dev/null\"\n"),
    )?;
    Ok(())
}

/// Spawn `apr` against an isolated `HOME`.
fn apr_command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apr"));
    cmd.env("HOME", home);
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
