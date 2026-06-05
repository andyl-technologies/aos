use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use aos_package::registry::keys;

#[test]
fn apr_keys_cli_manages_committed_roster() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let Some(registry_dir) = init_registry(&home, "core")? else {
        eprintln!("skipping apr keys CLI e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };

    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "1");

    let list = run_apr(&home, &["keys", "list", "--registry", "core"])?;
    assert!(list.contains("initial"));
    assert!(list.contains("active:"));

    run_apr(
        &home,
        &[
            "keys",
            "add",
            "next",
            "core:Ed25519:ZWZnaA==",
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["initial", "next"],
    );
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "2");

    let duplicate = run_apr_err(
        &home,
        &[
            "keys",
            "add",
            "next",
            "core:Ed25519:aGlqa2w=",
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&duplicate).contains("already exists"));

    run_apr(
        &home,
        &[
            "keys",
            "retire",
            "initial",
            "--reason",
            "planned rotation",
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["next"],
    );
    assert_eq!(roster.revoked.len(), 1);
    assert_eq!(roster.revoked[0].id, "initial");
    assert_eq!(
        roster.revoked[0].reason.as_deref(),
        Some("planned rotation")
    );
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "3");

    let last_key = run_apr_err(&home, &["keys", "retire", "next", "--registry", "core"])?;
    assert!(output_text(&last_key).contains("must keep an active survivor key"));

    let wrong_registry = run_apr_err(
        &home,
        &[
            "keys",
            "add",
            "foreign",
            "other:Ed25519:bW5vcA==",
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&wrong_registry).contains("expected 'core'"));

    run_apr(
        &home,
        &[
            "keys",
            "add",
            "third",
            "core:Ed25519:bW5vcA==",
            "--registry",
            "core",
        ],
    )?;
    run_apr(
        &home,
        &[
            "keys",
            "retire",
            "next",
            "--vouched-by",
            "third",
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["third"],
    );
    assert!(roster.revoked.iter().any(|entry| entry.id == "next"));

    Ok(())
}

fn init_registry(home: &Path, name: &str) -> Result<Option<PathBuf>> {
    let registry_dir = home
        .join(".local")
        .join("share")
        .join("apm")
        .join("registries")
        .join(name);
    fs::create_dir_all(&registry_dir)?;

    let init = Command::new("git")
        .args(["init", "--object-format=sha256"])
        .current_dir(&registry_dir)
        .output()
        .context("running git init --object-format=sha256")?;
    if !init.status.success() {
        return Ok(None);
    }

    git(
        &registry_dir,
        &["config", "user.email", "registry@example.com"],
    )?;
    git(&registry_dir, &["config", "user.name", "Registry Test"])?;
    git(&registry_dir, &["config", "commit.gpgsign", "false"])?;
    fs::write(
        registry_dir.join("registry.toml"),
        format!(
            r#"[registry]
name = "{name}"
"#,
        ),
    )?;
    fs::write(
        registry_dir.join("keys.toml"),
        format!(
            r#"schema = 1

[[keys]]
id = "initial"
key = "{name}:Ed25519:YWJjZA=="
"#,
        ),
    )?;
    git(&registry_dir, &["add", "-A"])?;
    git(&registry_dir, &["commit", "-m", "initial registry"])?;
    Ok(Some(registry_dir))
}

fn run_apr(home: &Path, args: &[&str]) -> Result<String> {
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
    Ok(output_text(&output))
}

fn run_apr_err(home: &Path, args: &[&str]) -> Result<Output> {
    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", home)
        .args(args)
        .output()
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if output.status.success() {
        bail!("apr {} unexpectedly succeeded", args.join(" "));
    }
    Ok(output)
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}
