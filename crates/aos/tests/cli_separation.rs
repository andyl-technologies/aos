//! Command-surface contracts for the three independent public CLIs.

use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use tempfile::tempdir;

fn run(binary: &str, arguments: &[&str]) -> Result<Output> {
    Command::new(binary)
        .args(arguments)
        .output()
        .with_context(|| format!("running {} {}", binary, arguments.join(" ")))
}

fn require_success(output: Output, description: &str) -> Result<String> {
    if !output.status.success() {
        bail!(
            "{description} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout).context("CLI help was not UTF-8")?)
}

#[test]
fn each_binary_identifies_its_own_command_surface() -> Result<()> {
    let aos = require_success(run(env!("CARGO_BIN_EXE_aos"), &["--help"])?, "aos --help")?;
    let apm = require_success(run(env!("CARGO_BIN_EXE_apm"), &["--help"])?, "apm --help")?;
    let apr = require_success(run(env!("CARGO_BIN_EXE_apr"), &["--help"])?, "apr --help")?;

    assert!(aos.starts_with("AOS build tool"));
    assert!(apm.starts_with("Consume and manage AOS packages"));
    assert!(apr.starts_with("Author and publish AOS package registries"));
    Ok(())
}

#[test]
fn commands_do_not_cross_public_cli_boundaries() -> Result<()> {
    assert!(
        !run(env!("CARGO_BIN_EXE_aos"), &["package", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(env!("CARGO_BIN_EXE_apm"), &["build", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(env!("CARGO_BIN_EXE_apr"), &["install", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(
            env!("CARGO_BIN_EXE_apm"),
            &["registry", "publish", "--help"]
        )?
        .status
        .success()
    );

    require_success(
        run(env!("CARGO_BIN_EXE_apm"), &["install", "--help"])?,
        "apm install --help",
    )?;
    require_success(
        run(env!("CARGO_BIN_EXE_apr"), &["publish", "--help"])?,
        "apr publish --help",
    )?;
    Ok(())
}

#[test]
fn system_scope_rejects_an_unidentified_target_before_loading_state() -> Result<()> {
    let root = tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_apm"))
        .args(["list", "--system"])
        .env("AOS_ROOT", root.path())
        .output()
        .context("running apm against an unidentified root")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is not an AOS root"),
        "unexpected system-target error: {stderr}"
    );
    Ok(())
}
