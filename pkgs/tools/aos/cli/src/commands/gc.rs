use anyhow::{Context, Result};

use crate::nix::NixRunner;
use crate::output::{create_spinner, Printer};

/// `aos gc` — garbage-collect old Nix store paths, or list generations.
pub fn run(nix: &NixRunner, printer: &Printer, list_generations: bool) -> Result<()> {
    if list_generations {
        return show_generations(nix, printer);
    }

    collect(nix, printer)
}

fn collect(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Collecting garbage (deleting generations older than 7 days)...");

    let spinner = create_spinner("collecting garbage");
    nix.collect_garbage(Some("7d"))
        .context("garbage collection")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "action": "gc",
        "older_than": "7d",
        "status": "complete",
    })) {
        return Ok(());
    }

    printer.success("Garbage collection complete");

    Ok(())
}

fn show_generations(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Listing system generations...");

    let output = nix
        .list_generations()
        .context("listing system generations")?;

    if printer.json_if_active(&serde_json::json!({
        "action": "list-generations",
        "output": output.trim(),
    })) {
        return Ok(());
    }

    printer.header("System generations:");
    printer.plain(output.trim());

    Ok(())
}
