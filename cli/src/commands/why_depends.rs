use anyhow::{Context, Result};

use aos::nix::NixRunner;
use aos::output::{create_spinner, Printer};

/// `aos why-depends <package> <dependency>` — trace why a package depends on
/// another.
pub fn run(nix: &NixRunner, printer: &Printer, package: &str, dependency: &str) -> Result<()> {
    let pkg_attr = format!("pkgs.{package}");
    let dep_attr = format!("pkgs.{dependency}");

    printer.info(&format!(
        "Building '{package}' and '{dependency}' to resolve store paths..."
    ));

    // Build both packages so we have their store paths.
    let spinner = create_spinner(&format!("building {package}"));
    let pkg_path = nix
        .build(&pkg_attr, None)
        .with_context(|| format!("building '{package}'"))?;
    spinner.finish_and_clear();

    let spinner = create_spinner(&format!("building {dependency}"));
    let dep_path = nix
        .build(&dep_attr, None)
        .with_context(|| format!("building '{dependency}'"))?;
    spinner.finish_and_clear();

    // Get the full referrer closure of the package and search for the
    // dependency in it.
    printer.info("Tracing dependency chain...");

    let spinner = create_spinner("querying referrers closure");
    let requisites = nix
        .store_query(&pkg_path, &["--query", "--requisites"])
        .context("querying requisites")?;
    spinner.finish_and_clear();

    let dep_path_str = dep_path.to_string_lossy().to_string();

    // Check if the dependency is actually in the closure.
    let found = requisites.lines().any(|line| line.trim() == dep_path_str);

    if !found {
        if printer.json_if_active(&serde_json::json!({
            "package": package,
            "dependency": dependency,
            "depends": false,
        })) {
            return Ok(());
        }

        printer.warning(&format!(
            "'{package}' does not depend on '{dependency}'"
        ));
        return Ok(());
    }

    // Get the referrers of the dependency within the package closure to show
    // what directly references it.
    let spinner = create_spinner("finding direct referrers");
    let referrers = nix
        .store_query(&dep_path, &["--query", "--referrers"])
        .context("querying referrers")?;
    spinner.finish_and_clear();

    // Filter referrers to only those that are also in the package's closure.
    let requisites_set: std::collections::HashSet<&str> =
        requisites.lines().map(|l| l.trim()).collect();

    let chain: Vec<&str> = referrers
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && requisites_set.contains(l))
        .collect();

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "dependency": dependency,
        "depends": true,
        "package_path": pkg_path.to_string_lossy(),
        "dependency_path": dep_path_str,
        "referrers_in_closure": chain,
    })) {
        return Ok(());
    }

    printer.header(&format!(
        "'{package}' depends on '{dependency}'"
    ));
    printer.kv("Package", &pkg_path.to_string_lossy());
    printer.kv("Dependency", &dep_path_str);
    printer.plain("");
    printer.header("Direct referrers in closure:");

    if chain.is_empty() {
        printer.plain(&format!("  {}", pkg_path.display()));
        printer.plain(&format!("    -> {}", dep_path.display()));
    } else {
        for referrer in &chain {
            printer.plain(&format!("  {referrer}"));
        }
    }

    Ok(())
}
