//! Command-surface contracts for public CLIs and installed private helpers.

use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

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
    assert!(
        !run(env!("CARGO_BIN_EXE_apm"), &["__eval", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(env!("CARGO_BIN_EXE_apm"), &["--json", "__eval", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(env!("CARGO_BIN_EXE_apm"), &["apply-deployment", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(
            env!("CARGO_BIN_EXE_aos-package-runtime"),
            &["install", "--help"]
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
    require_success(
        run(
            env!("CARGO_BIN_EXE_aos-package-runtime"),
            &["apply-deployment", "--help"],
        )?,
        "aos-package-runtime apply-deployment --help",
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

#[test]
fn native_deployment_dispatch_stays_private_and_rejects_retired_stage_commands() -> Result<()> {
    for command in [
        "apply-deployment",
        "verify-deployment",
        "deployment-current",
        "deployment-result",
    ] {
        for arguments in [vec![command, "--help"], vec!["--json", command, "--help"]] {
            assert!(!run(env!("CARGO_BIN_EXE_apm"), &arguments)?.status.success());
            require_success(
                run(env!("CARGO_BIN_EXE_aos-package-runtime"), &arguments)?,
                &format!("native runtime {command} help"),
            )?;
        }
    }

    for command in [
        "__ability-materialize-source-stage",
        "__ability-stage-run",
        "__ability-stage-validate",
        "__ability-stage-receive",
    ] {
        for binary in [
            env!("CARGO_BIN_EXE_apm"),
            env!("CARGO_BIN_EXE_aos-package-runtime"),
        ] {
            assert!(!run(binary, &[command, "--help"])?.status.success());
        }
    }

    Ok(())
}

#[test]
fn image_preparation_is_public_and_rejects_container_before_state_access() -> Result<()> {
    let help = require_success(
        run(env!("CARGO_BIN_EXE_apm"), &["image", "prepare", "--help"])?,
        "apm image prepare help",
    )?;
    assert!(help.contains("--qualified"));
    assert!(
        !run(env!("CARGO_BIN_EXE_aos"), &["image", "prepare", "--help"])?
            .status
            .success()
    );
    assert!(
        !run(
            env!("CARGO_BIN_EXE_aos-package-runtime"),
            &["image", "prepare", "--help"]
        )?
        .status
        .success()
    );

    let home = tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_apm"))
        .args(["image", "prepare", "server", "--dry-run", "--yes"])
        .env_clear()
        .env("HOME", home.path())
        .env("AOS_RUNTIME", "container")
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("AOS containers support only user-scope")
    );
    assert_eq!(std::fs::read_dir(home.path())?.count(), 0);
    Ok(())
}

#[cfg(unix)]
fn run_boot_entry(binary: &str, entry: &str, arguments: &[&str]) -> Result<Output> {
    Command::new(binary)
        .arg0(entry)
        .env_clear()
        .env("TOKIO_WORKER_THREADS", "2")
        .args(arguments)
        .output()
        .with_context(|| format!("running boot entry {entry}"))
}

#[cfg(unix)]
#[test]
fn shared_boot_entry_preserves_host_and_handoff_command_surfaces() -> Result<()> {
    for entry in [
        "aos-boot-configuration",
        ".aos-boot-configuration-unwrapped",
    ] {
        for arguments in [vec!["--help"], vec!["handoff-initrd-store", "--help"]] {
            let standalone = run_boot_entry(
                env!("CARGO_BIN_EXE_aos-boot-configuration"),
                entry,
                &arguments,
            )?;
            let shared = run_boot_entry(env!("CARGO_BIN_EXE_apm"), entry, &arguments)?;

            assert!(standalone.status.success());
            assert!(shared.status.success());
            assert_eq!(shared.stdout, standalone.stdout);
            assert_eq!(shared.stderr, standalone.stderr);
            assert!(String::from_utf8_lossy(&shared.stdout).contains("--admission-sha256"));
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn shared_boot_entry_preserves_source_rejection_before_state_access() -> Result<()> {
    let root = tempdir()?;
    let input = root.path().to_str().context("fixture path is not UTF-8")?;
    let digest = format!("sha256:{}", "0".repeat(64));
    let arguments = [
        "--input",
        input,
        "--state-directory",
        input,
        "--nix-store",
        "/unreachable/bin/nix-store",
        "--admission",
        input,
        "--admission-sha256",
        &digest,
    ];

    let standalone = run_boot_entry(
        env!("CARGO_BIN_EXE_aos-boot-configuration"),
        "aos-boot-configuration",
        &arguments,
    )?;
    let shared = run_boot_entry(
        env!("CARGO_BIN_EXE_apm"),
        ".aos-boot-configuration-unwrapped",
        &arguments,
    )?;

    assert_eq!(standalone.status.code(), Some(1));
    assert_eq!(shared.status.code(), Some(1));
    assert!(shared.stdout.is_empty());
    assert_eq!(shared.stderr, standalone.stderr);
    assert!(String::from_utf8_lossy(&shared.stderr).contains(
        "aos-boot-configuration: host metadata adoption requires the fixed verified image and system profile"
    ));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}
