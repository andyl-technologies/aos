use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::{create_spinner, Printer};

/// `aos lint [package]` — lint the repository's Nix sources.
///
/// Builds the `checks.lint` derivation, which enforces AOS's hermeticity
/// and convention rules across every `.nix` file (see
/// `lib/testing/nix-lint.nix`). The linter always scans the whole tree;
/// the optional `package` argument is accepted for forward compatibility
/// but does not yet scope the scan.
pub fn run(nix: &NixRunner, printer: &Printer, package: Option<&str>) -> Result<()> {
    let (attr, label) = ("checks.lint".to_string(), "Nix lint checks".to_string());

    if let Some(pkg) = package {
        printer.info(&format!(
            "Per-package lint scoping is not yet supported; linting the whole tree (ignoring '{pkg}')."
        ));
    }

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
