//! `aos test` — run the repository's test layers.
//!
//! Tests are Nix derivations under the `checks` attribute, grouped into
//! four layers of increasing cost: `eval` (pure evaluation checks),
//! `build` (package build checks), `vm` (QEMU VM integration tests), and
//! `fleet` (multi-VM fleet tests). A subcommand runs one layer
//! (optionally a single named suite); with no subcommand, all four run
//! in sequence with a pass/fail summary. Concurrency maps to
//! `nix-build --max-jobs`, defaulting to the host CPU count.
//!
//! `aos test fleet <suite> --interactive` is special: it builds the
//! suite's `driverInteractive` launcher and `exec`s it, booting the
//! fleet outside the Nix sandbox with SSH access for debugging.

use std::os::unix::process::CommandExt;
use std::thread::available_parallelism;

use anyhow::{Context, Result};

use crate::cli::TestCmd;
use aos_core::nix::NixRunner;
use aos_core::output::{Printer, create_spinner};

/// Resolve the concurrency cap for `aos test`.
///
/// `aos test -j N` wins. With no override, default to host CPU count
/// (`nproc`); the harness is race-free at any concurrency (per-driver-
/// PID mcast endpoint in aos_test_driver/qemu.py, per-PID vsock CID in
/// firecracker.py, system-ready gate in __main__.py), so the default
/// just makes the most of the box. Falls back to 1 if the platform
/// refuses to report parallelism — pre-change behaviour was effectively
/// serial, so a single-job floor preserves it.
fn resolve_jobs(explicit: Option<usize>) -> usize {
    if let Some(n) = explicit {
        return n.max(1);
    }
    available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Validate that a test suite name contains only safe characters for
/// interpolation into Nix attribute paths.
fn validate_suite_name(suite: &str) -> Result<()> {
    if !suite
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!("invalid test suite name: {suite}");
    }
    Ok(())
}

/// Loose sanity check on an SSH public key string. Rejects empty input
/// and anything that doesn't start with one of the OpenSSH key-type
/// prefixes — full pubkey parsing is left to sshd inside the guest.
fn validate_pubkey_string(key: &str) -> Result<()> {
    if key.is_empty() {
        anyhow::bail!("--ssh-authorized-key must not be empty");
    }
    if key.contains('\n') {
        anyhow::bail!("--ssh-authorized-key must be a single line");
    }
    if !key.starts_with("ssh-")
        && !key.starts_with("ecdsa-")
        && !key.starts_with("sk-ssh-")
        && !key.starts_with("sk-ecdsa-")
    {
        anyhow::bail!(
            "--ssh-authorized-key does not look like an OpenSSH public key \
             (expected a line starting with `ssh-…`, `ecdsa-…`, or `sk-…`)"
        );
    }
    Ok(())
}

/// Escape a string for embedding inside a Nix double-quoted string literal.
/// Covers the four sequences Nix interprets: `\\`, `\"`, `\${`, and `\n`.
fn nix_string_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            // Forbid the `${...}` antiquote sequence by escaping the `$`
            // whenever it precedes a `{`. Cheaper to escape every `$` —
            // the result is still a valid string literal and identical
            // when read back.
            '$' => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `aos test [subcommand]` — run test layers.
///
/// Runs the selected layer (or all layers when `cmd` is `None`) at the
/// resolved concurrency.
///
/// # Errors
///
/// Returns an error if a suite name or SSH key fails validation, if any
/// test derivation fails to build (i.e. a test fails), or — in the
/// `--interactive` fleet case — if the launcher cannot be built or
/// `exec`ed.
pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    cmd: &Option<TestCmd>,
    jobs: Option<usize>,
) -> Result<()> {
    let jobs = resolve_jobs(jobs);
    match cmd {
        Some(TestCmd::Eval) => run_layer(nix, printer, "checks.eval", "eval", jobs),
        Some(TestCmd::Build) => run_layer(nix, printer, "checks.build", "build", jobs),
        Some(TestCmd::Vm { suite }) => {
            let attr = match suite {
                Some(s) => {
                    validate_suite_name(s)?;
                    format!("checks.vm.{s}")
                }
                None => "checks.vm".to_string(),
            };
            let label = match suite {
                Some(s) => format!("vm/{s}"),
                None => "vm".to_string(),
            };
            run_layer(nix, printer, &attr, &label, jobs)
        }
        Some(TestCmd::Fleet {
            suite,
            interactive,
            ssh_authorized_key,
        }) => {
            if *interactive {
                return run_fleet_interactive(
                    nix,
                    printer,
                    suite.as_deref(),
                    ssh_authorized_key.as_deref(),
                );
            }
            let attr = match suite {
                Some(s) => {
                    validate_suite_name(s)?;
                    format!("checks.fleet.{s}")
                }
                None => "checks.fleet".to_string(),
            };
            let label = match suite {
                Some(s) => format!("fleet/{s}"),
                None => "fleet".to_string(),
            };
            run_layer(nix, printer, &attr, &label, jobs)
        }
        None => run_all(nix, printer, jobs),
    }
}

/// Run all test layers sequentially and produce a summary.
fn run_all(nix: &NixRunner, printer: &Printer, jobs: usize) -> Result<()> {
    let layers: &[(&str, &str)] = &[
        ("checks.eval", "eval"),
        ("checks.build", "build"),
        ("checks.vm", "vm"),
        ("checks.fleet", "fleet"),
    ];

    let total = layers.len();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for (i, (attr, label)) in layers.iter().enumerate() {
        printer.step(i + 1, total, &format!("Running {label} tests..."));

        let spinner = create_spinner(&format!("testing {label}"));
        let result = nix
            .build_with_max_jobs(attr, None, jobs)
            .with_context(|| format!("test layer '{label}'"));
        spinner.finish_and_clear();

        match result {
            Ok(_) => {
                printer.success(&format!("  {label}: passed"));
                passed += 1;
            }
            Err(err) => {
                printer.error(&format!("  {label}: FAILED"));
                if printer.mode() == aos_core::output::OutputMode::Verbose {
                    printer.plain(&format!("    {err:#}"));
                }
                failures.push(label.to_string());
                failed += 1;
            }
        }
    }

    // Summary.
    printer.plain("");
    printer.header("Test Summary");
    printer.kv("Passed", &passed.to_string());
    printer.kv("Failed", &failed.to_string());

    if printer.json_if_active(&serde_json::json!({
        "passed": passed,
        "failed": failed,
        "failures": failures,
    })) {
        if failed > 0 {
            anyhow::bail!("{failed} test layer(s) failed");
        }
        return Ok(());
    }

    if failed > 0 {
        printer.error(&format!(
            "{failed} test layer(s) failed: {}",
            failures.join(", ")
        ));
        anyhow::bail!("{failed} test layer(s) failed");
    }

    printer.success("All tests passed");
    Ok(())
}

/// `aos test fleet <suite> --interactive --ssh-authorized-key <key>`.
///
/// Builds `checks.fleet.<suite>.driverInteractive <key>` (a function on the
/// fleet test derivation that returns the launcher derivation) and `exec`s
/// the resulting `bin/run-fleet-interactive`. The launcher boots QEMU
/// outside the sandbox; the user reaches each guest's sshd over the
/// per-machine TCP forward printed by the launcher banner.
fn run_fleet_interactive(
    nix: &NixRunner,
    printer: &Printer,
    suite: Option<&str>,
    ssh_authorized_key: Option<&str>,
) -> Result<()> {
    let suite =
        suite.context("--interactive requires a fleet suite name (e.g. `aos test fleet k3s-combined-worker --interactive …`)")?;
    validate_suite_name(suite)?;
    let key = ssh_authorized_key.context("--interactive requires --ssh-authorized-key")?;
    validate_pubkey_string(key)?;

    let root = nix.root().to_string_lossy().to_string();
    let expr = format!(
        "((import {root_lit} {{}}).checks.fleet.{suite}.driverInteractive) {key_lit}",
        root_lit = nix_string_quote(&root),
        suite = suite,
        key_lit = nix_string_quote(key),
    );

    printer.info(&format!("Building interactive driver for fleet/{suite}..."));
    let spinner = create_spinner(&format!("building fleet/{suite} driverInteractive"));
    let store_path = nix
        .build_expr(&expr)
        .with_context(|| format!("build fleet/{suite} driverInteractive"));
    spinner.finish_and_clear();
    let store_path = store_path?;

    let script = store_path.join("bin/run-fleet-interactive");
    if !script.is_file() {
        anyhow::bail!(
            "driverInteractive build did not produce a launcher at {}",
            script.display()
        );
    }

    printer.success(&format!("Launching fleet/{suite} (Ctrl-C to shut down)"));

    // The launcher is a hermetically compiled trampoline that resets
    // inherited SIGINT/SIGQUIT dispositions before starting its Bash payload.
    // Replace this process so signals reach that launcher directly; `exec`
    // only returns on failure.
    let err = std::process::Command::new(&script).exec();
    Err(anyhow::anyhow!("exec({}): {err}", script.display()))
}

/// Run a single test layer at the given concurrency.
fn run_layer(
    nix: &NixRunner,
    printer: &Printer,
    attr: &str,
    label: &str,
    jobs: usize,
) -> Result<()> {
    printer.info(&format!("Running {label} tests (max-jobs={jobs})..."));

    let spinner = create_spinner(&format!("testing {label}"));
    let result = nix
        .build_with_max_jobs(attr, None, jobs)
        .with_context(|| format!("test layer '{label}'"));
    spinner.finish_and_clear();

    match result {
        Ok(store_path) => {
            if printer.json_if_active(&serde_json::json!({
                "layer": label,
                "status": "pass",
                "store_path": store_path.to_string_lossy(),
            })) {
                return Ok(());
            }

            printer.success(&format!("Test layer '{label}' passed"));
            Ok(())
        }
        Err(err) => {
            if printer.json_if_active(&serde_json::json!({
                "layer": label,
                "status": "fail",
                "error": format!("{err:#}"),
            })) {
                return Err(err);
            }

            printer.error(&format!("Test layer '{label}' FAILED"));
            Err(err)
        }
    }
}
