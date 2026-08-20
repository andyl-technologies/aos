//! `aos graph` — display a package's dependency graph.
//!
//! Builds the package first (dependency information lives in the Nix
//! store database, so the store path must exist), then queries the store
//! with `--query --tree` for the default indented tree view or
//! `--query --graph` for `--dot`, whose raw DOT output goes straight to
//! stdout for piping into graphviz.

use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos graph <package>` — display the dependency graph for a package.
///
/// # Errors
///
/// Returns an error if building the package or querying the store for
/// its dependency graph fails.
pub fn run(nix: &NixRunner, printer: &Printer, package: &str, dot: bool) -> Result<()> {
    let attr = format!("pkgs.{package}");

    printer.info(&format!("Building '{package}' to resolve dependencies..."));

    let spinner = printer.activity(&format!("building {package}"));
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

/// Emit the dependency graph in DOT format on stdout (graphviz-ready).
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

/// Print the dependency graph as an indented tree.
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
