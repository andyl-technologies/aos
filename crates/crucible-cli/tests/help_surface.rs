//! Process-level checks for the CLI help, version, and completions surfaces.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::process::Command;

#[test]
fn cli_help_process_outputs_top_level_surface() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .arg("--help")
        .output()?;
    assert!(
        output.status.success(),
        "crucible --help should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    for needle in [
        "Run and inspect Crucible simulations.",
        "run",
        "verify",
        "selftest",
        "save",
        "resume",
        "fork",
        "replay",
        "search",
        "fuzz",
        "triage",
        "debug",
        "serve",
        "completions",
        "--seed <u64|hex>",
        "--backend <auto|qemu|double>",
        "--format <jsonl|json|table|markdown>",
        "--artifact-dir <path>",
    ] {
        assert!(
            stdout.contains(needle),
            "process help is missing `{needle}`:\n{stdout}",
        );
    }
    assert!(
        output.stderr.is_empty(),
        "crucible --help should not write stderr, got `{}`",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[test]
fn cli_help_process_version_exits_zero() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .arg("--version")
        .output()?;
    assert!(
        output.status.success(),
        "crucible --version should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("crucible"),
        "version output must name the binary: {stdout}",
    );
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output must contain the crate version: {stdout}",
    );
    assert!(
        output.stderr.is_empty(),
        "crucible --version should not write stderr, got `{}`",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[test]
fn cli_completions_process_emits_bash_script() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["completions", "bash"])
        .output()?;
    assert!(
        output.status.success(),
        "crucible completions bash should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    for needle in ["_crucible", "completions", "verify", "complete -F"] {
        assert!(
            stdout.contains(needle),
            "bash completions are missing `{needle}`:\n{stdout}",
        );
    }
    assert!(
        output.stderr.is_empty(),
        "crucible completions bash should not write stderr, got `{}`",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[test]
fn cli_help_process_hides_gate_only_flags() -> Result<(), Box<dyn Error>> {
    for (subcommand, hidden_flag) in [
        ("run", "--emit-mock-failure-artifact"),
        ("search", "--retained-evidence"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args([subcommand, "--help"])
            .output()?;
        assert!(
            output.status.success(),
            "crucible {subcommand} --help should exit 0; stdout=`{}` stderr=`{}`",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            !stdout.contains(hidden_flag),
            "hidden gate-only flag `{hidden_flag}` must stay out of {subcommand} help:\n{stdout}",
        );
        assert!(
            output.stderr.is_empty(),
            "crucible {subcommand} --help should not write stderr, got `{}`",
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

#[test]
fn cli_completions_process_rejects_missing_shell() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .arg("completions")
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(64),
        "crucible completions without a shell should exit 64; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stdout.is_empty(),
        "usage failures should not write stdout, got `{}`",
        String::from_utf8_lossy(&output.stdout),
    );
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("required") && stderr.contains("<SHELL>"),
        "missing shell error should identify the required SHELL argument:\n{stderr}",
    );
    Ok(())
}
