use anyhow::{Context, Result};

use crate::cli::TestCmd;
use aos_core::nix::NixRunner;
use aos_core::output::{create_spinner, Printer};

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

/// `aos test [subcommand]` — run test layers.
pub fn run(nix: &NixRunner, printer: &Printer, cmd: &Option<TestCmd>) -> Result<()> {
    match cmd {
        Some(TestCmd::Eval) => run_layer(nix, printer, "checks.eval", "eval"),
        Some(TestCmd::Build) => run_layer(nix, printer, "checks.build", "build"),
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
            run_layer(nix, printer, &attr, &label)
        }
        Some(TestCmd::Fleet { suite }) => {
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
            run_layer(nix, printer, &attr, &label)
        }
        None => run_all(nix, printer),
    }
}

/// Run all test layers sequentially and produce a summary.
fn run_all(nix: &NixRunner, printer: &Printer) -> Result<()> {
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
        let result = nix.build(attr, None).with_context(|| format!("test layer '{label}'"));
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

/// Run a single test layer.
fn run_layer(nix: &NixRunner, printer: &Printer, attr: &str, label: &str) -> Result<()> {
    printer.info(&format!("Running {label} tests..."));

    let spinner = create_spinner(&format!("testing {label}"));
    let result = nix.build(attr, None).with_context(|| format!("test layer '{label}'"));
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
