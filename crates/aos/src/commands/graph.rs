use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::{Printer, create_spinner};

/// `aos graph <package>` — display the dependency graph for a package.
pub fn run(nix: &NixRunner, printer: &Printer, package: &str, dot: bool) -> Result<()> {
    let attr = format!("pkgs.{package}");

    printer.info(&format!("Building '{package}' to resolve dependencies..."));

    let spinner = create_spinner(&format!("building {package}"));
    let store_path = nix
        .build(&attr, None)
        .with_context(|| format!("building '{package}' for dependency graph"))?;
    spinner.finish_and_clear();

    if dot {
        output_dot(nix, printer, package, &store_path)
    } else {
        output_tree(nix, printer, package, &store_path)
    }
}

fn output_dot(
    nix: &NixRunner,
    printer: &Printer,
    package: &str,
    store_path: &std::path::Path,
) -> Result<()> {
    printer.info(&format!("Generating DOT graph for '{package}'..."));

    let graph = nix
        .store_query(store_path, &["--query", "--graph"])
        .with_context(|| format!("querying dependency graph for '{package}'"))?;

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "format": "dot",
        "graph": graph,
    })) {
        return Ok(());
    }

    // DOT output goes to stdout so it can be piped to graphviz.
    print!("{graph}");

    Ok(())
}

fn output_tree(
    nix: &NixRunner,
    printer: &Printer,
    package: &str,
    store_path: &std::path::Path,
) -> Result<()> {
    printer.info(&format!("Querying dependency tree for '{package}'..."));

    let tree = nix
        .store_query(store_path, &["--query", "--tree"])
        .with_context(|| format!("querying dependency tree for '{package}'"))?;

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "format": "tree",
        "tree": tree,
    })) {
        return Ok(());
    }

    printer.header(&format!("Dependencies for {package}:"));
    printer.plain(&tree);

    Ok(())
}
