use anyhow::{Context, Result};

use crate::error::AosError;
use crate::nix::NixRunner;
use crate::output::{create_spinner, Printer};

/// `aos build <package>` or `aos build --all`.
pub fn run(nix: &NixRunner, printer: &Printer, package: Option<&str>, all: bool) -> Result<()> {
    if all {
        return build_all(nix, printer);
    }

    let package = package.ok_or_else(|| AosError::InvalidArgument {
        message: "provide a package name, or use --all to build everything".to_string(),
    })?;

    let attr = format!("pkgs.{package}");

    printer.info(&format!("Building package '{package}'..."));

    let spinner = create_spinner(&format!("building {package}"));
    let store_path = nix
        .build(&attr, None)
        .with_context(|| format!("building package '{package}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!(
        "Built {package} -> {}",
        store_path.display()
    ));

    Ok(())
}

fn build_all(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Building all packages...");

    let spinner = create_spinner("building all packages");
    let paths = nix
        .build_all("pkgs")
        .context("building all packages")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "packages": paths.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
        "count": paths.len(),
    })) {
        return Ok(());
    }

    for path in &paths {
        printer.plain(&format!("  {}", path.display()));
    }

    printer.success(&format!("Built {} packages", paths.len()));

    Ok(())
}
