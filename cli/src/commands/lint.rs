use anyhow::{Context, Result};

use aos::nix::NixRunner;
use aos::output::{create_spinner, Printer};

/// `aos lint [package]` — validate package definitions.
pub fn run(nix: &NixRunner, printer: &Printer, package: Option<&str>) -> Result<()> {
    let (attr, label) = match package {
        Some(pkg) => (format!("checks.lint.{pkg}"), format!("lint check for '{pkg}'")),
        None => ("checks.lint".to_string(), "all lint checks".to_string()),
    };

    printer.info(&format!("Running {label}..."));

    let spinner = create_spinner(&format!("running {label}"));
    let result = nix.build(&attr, None).with_context(|| format!("running {label}"));
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
