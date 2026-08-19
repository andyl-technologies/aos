//! `aos lint` — validate package definitions.
//!
//! The lint rules are implemented in Nix: this command simply builds the
//! `checks.lint` attribute (or `checks.lint.<package>` for a single
//! package) and reports pass/fail. A failed lint derivation surfaces as
//! a build error with the rule output in the build log.

use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos lint [package]` — validate package definitions.
///
/// # Errors
///
/// Returns an error if the lint check derivation fails to build, i.e.
/// when a lint rule is violated (or the evaluation itself fails).
pub fn run(nix: &NixRunner, printer: &Printer, package: Option<&str>) -> Result<()> {
    let (attr, label) = match package {
        Some(pkg) => (
            format!("checks.lint.{pkg}"),
            format!("lint check for '{pkg}'"),
        ),
        None => ("checks.lint".to_string(), "all lint checks".to_string()),
    };

    printer.info(&format!("Running {label}..."));

    let spinner = printer.activity(&format!("running {label}"));
    let result = nix
        .build(&attr, None)
        .with_context(|| format!("running {label}"));
    spinner.finish_and_clear();

    match result {
        Ok(store_path) => {
            if printer.json_if_active(&serde_json::json!({
                "lint": package.unwrap_or("all"),
                "status": "pass",
                "store_path": store_path.to_string_lossy(),
            })) {
                return Ok(());
            }

            printer.success(&format!("Lint passed: {label}"));
            Ok(())
        }
        Err(err) => {
            if printer.json_if_active(&serde_json::json!({
                "lint": package.unwrap_or("all"),
                "status": "fail",
                "error": format!("{err:#}"),
            })) {
                // Return the error so the exit code is non-zero.
                return Err(err);
            }

            printer.error(&format!("Lint failed: {label}"));
            Err(err)
        }
    }
}
