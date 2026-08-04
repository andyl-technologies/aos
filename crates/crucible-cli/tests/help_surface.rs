//! Process-level checks for the CLI help, version, and completions surfaces.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::process::Command;

#[cfg(feature = "test-double")]
const BACKEND_HELP: &str = "--backend <auto|qemu|double>";
#[cfg(not(feature = "test-double"))]
const BACKEND_HELP: &str = "--backend <auto|qemu>";

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
        "Root entropy (06 §5.3). Overrides CRUCIBLE_SEED",
        BACKEND_HELP,
        "Local backend (20 §10). Default: auto",
        "Talk to a daemon (21) instead of running in-process",
        "Patched QEMU system binary (26). Else discovered",
        "crucible-qemu-plugin cdylib (12, 26). Else discovered",
        "Content-addressed store root (06, 07). Else default",
        "--format <jsonl|json|table|markdown>",
        "Trace/report render format. Default: table on a terminal, otherwise jsonl",
        "Write the event-log stream here. Default: stdout",
        "--artifact-dir <path>",
        "Where failure artifacts are written. Default: ./.crucible",
        "Increase log verbosity (repeatable: -vv)",
        "Suppress non-essential output",
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

#[cfg(not(feature = "test-double"))]
#[test]
fn cli_production_build_rejects_the_test_double_backend() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--backend", "double", "run", "scenario.toml"])
        .output()?;

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("invalid value 'double'"));

    Ok(())
}

#[cfg(not(feature = "test-double"))]
#[test]
fn cli_production_build_rejects_the_mock_failure_gate_flag() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["run", "scenario.toml", "--emit-mock-failure-artifact"])
        .output()?;

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("unexpected argument '--emit-mock-failure-artifact'"));

    Ok(())
}

#[cfg(not(feature = "test-double"))]
#[test]
fn cli_production_selftest_help_excludes_test_double_options() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["selftest", "--help"])
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Run the packaged determinism gates"));
    assert!(!stdout.contains("--with-qemu"));
    assert!(!stdout.contains("double"));
    assert!(!stdout.contains("--corpus"));

    Ok(())
}

#[test]
fn cli_help_process_version_exits_zero() -> Result<(), Box<dyn Error>> {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .arg(flag)
            .output()?;
        assert!(
            output.status.success(),
            "crucible {flag} should exit 0; stdout=`{}` stderr=`{}`",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert_eq!(
            stdout,
            format!("crucible {}\n", env!("CARGO_PKG_VERSION")),
            "version output must exactly name the binary and crate version",
        );
        assert!(
            output.stderr.is_empty(),
            "crucible {flag} should not write stderr, got `{}`",
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

#[test]
fn cli_completions_process_emits_every_supported_shell_script() -> Result<(), Box<dyn Error>> {
    for (shell, marker) in [
        ("bash", "complete -F"),
        ("elvish", "set edit:completion:arg-completer[crucible]"),
        ("fish", "complete -c crucible"),
        ("powershell", "Register-ArgumentCompleter"),
        ("zsh", "#compdef crucible"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["completions", shell])
            .output()?;
        assert!(
            output.status.success(),
            "crucible completions {shell} should exit 0; stdout=`{}` stderr=`{}`",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout)?;
        for needle in ["crucible", "completions", "verify", marker] {
            assert!(
                stdout.contains(needle),
                "{shell} completions are missing `{needle}`:\n{stdout}",
            );
        }
        assert!(
            output.stderr.is_empty(),
            "crucible completions {shell} should not write stderr, got `{}`",
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

#[test]
fn cli_help_process_outputs_every_normative_subcommand_surface() -> Result<(), Box<dyn Error>> {
    for (subcommand, expected) in [
        ("run", "--until <quiescence|virtual-time|property|stopped>"),
        ("verify", "--compare <a> <b>"),
        ("selftest", "--gates <list>"),
        ("save", "--at <virtual-time|quiescence|property|marker>"),
        ("resume", "<SAVEPOINT>"),
        ("fork", "--override <decision=value>"),
        ("replay", "--check <original-log>"),
        ("search", "--strategy <bfs|dfs|guided>"),
        ("fuzz", "<FAMILY|--family <path|hash>>"),
        ("serve", "--listen <addr>"),
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
            stdout.contains(expected),
            "{subcommand} help is missing `{expected}`:\n{stdout}",
        );
        assert!(output.stderr.is_empty());
    }
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

#[test]
fn cli_process_rejects_every_missing_normative_input() -> Result<(), Box<dyn Error>> {
    for (label, args, expected) in [
        ("run scenario", &["run"][..], "<SCENARIO>"),
        (
            "run virtual-time budget",
            &["run", "builtin:happy-path.scn", "--until", "virtual-time"][..],
            "--max-virtual-time <dur>",
        ),
        (
            "verify input",
            &["verify"][..],
            "<SCENARIO|--compare <a> <b>>",
        ),
        (
            "save scenario",
            &["save", "--at", "quiescence"][..],
            "<SCENARIO>",
        ),
        (
            "save boundary",
            &["save", "builtin:happy-path.scn"][..],
            "--at <virtual-time|quiescence|property|marker>",
        ),
        (
            "save virtual-time budget",
            &["save", "builtin:happy-path.scn", "--at", "virtual-time"][..],
            "--max-virtual-time <dur>",
        ),
        (
            "save property selector",
            &["save", "builtin:happy-path.scn", "--at", "property"][..],
            "--property <assertion>",
        ),
        (
            "save marker selector",
            &["save", "builtin:happy-path.scn", "--at", "marker"][..],
            "--marker <name>",
        ),
        ("resume savepoint", &["resume"][..], "<SAVEPOINT>"),
        (
            "resume virtual-time budget",
            &["resume", "blake3:savepoint", "--until", "virtual-time"][..],
            "--max-virtual-time <dur>",
        ),
        ("fork savepoint", &["fork"][..], "<SAVEPOINT>"),
        (
            "fork virtual-time budget",
            &["fork", "blake3:savepoint", "--until", "virtual-time"][..],
            "--max-virtual-time <dur>",
        ),
        ("replay artifact", &["replay"][..], "<ARTIFACT>"),
        ("search scenario", &["search"][..], "<SCENARIO>"),
        (
            "fuzz family",
            &["fuzz"][..],
            "<FAMILY|--family <path|hash>>",
        ),
        ("serve listener", &["serve"][..], "--listen <addr>"),
        (
            "debug target",
            &["debug"][..],
            "<ARTIFACT|SAVEPOINT|--session <ADDR>>",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(args)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(64),
            "missing {label} must exit 64; stdout=`{}` stderr=`{}`",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            output.stdout.is_empty(),
            "missing {label} must not write stdout: `{}`",
            String::from_utf8_lossy(&output.stdout),
        );
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains("required") && stderr.contains(expected),
            "missing {label} must identify `{expected}` as required:\n{stderr}",
        );
    }
    Ok(())
}

#[test]
fn cli_process_rejects_normative_conflicts_and_incomplete_alternatives()
-> Result<(), Box<dyn Error>> {
    for (label, args) in [
        (
            "verify scenario plus comparison",
            &["verify", "scenario.toml", "--compare", "left", "right"][..],
        ),
        (
            "incomplete verify comparison",
            &["verify", "--compare", "left"][..],
        ),
        (
            "fuzz positional plus flag family",
            &["fuzz", "family.toml", "--family", "blake3:family"][..],
        ),
        (
            "fork seed plus decision override",
            &[
                "fork",
                "blake3:savepoint",
                "--seed",
                "1",
                "--override",
                "decision=value",
            ][..],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(args)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(64),
            "{label} must exit 64; stdout=`{}` stderr=`{}`",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(output.stdout.is_empty(), "{label} wrote stdout");
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains("cannot be used with") || stderr.contains("required"),
            "{label} did not explain the usage failure:\n{stderr}",
        );
    }
    Ok(())
}
