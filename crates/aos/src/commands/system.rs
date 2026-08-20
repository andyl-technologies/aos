//! `aos system` — operations on the system configuration.
//!
//! Three subcommands, all driven by the module system's evaluated
//! config:
//!
//! - `build` — build `system.config.system.build.toplevel` (the /etc,
//!   systemd units, and package symlinks for the system).
//! - `image` — build the bootable disk image and link it at
//!   `output/aos.raw`.
//! - `eval` — evaluate `system.config` to JSON and pretty-print it.

use anyhow::{Context, Result};

use crate::cli::SystemCmd;
use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos system <build|image|eval>` — dispatch to the system operation.
///
/// # Errors
///
/// Returns an error if the underlying Nix build or evaluation fails.
pub fn run(nix: &NixRunner, printer: &Printer, cmd: &SystemCmd) -> Result<()> {
    match cmd {
        SystemCmd::Build => build(nix, printer),
        SystemCmd::Image => image(nix, printer),
        SystemCmd::Eval => eval(nix, printer),
    }
}

/// Build the system toplevel derivation and print its store path.
fn build(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "system.config.system.build.toplevel";

    printer.info("Building system...");

    let spinner = printer.activity("building system");
    let store_path = nix.build(attr, None).with_context(|| "building system")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!("Built system -> {}", store_path.display()));

    Ok(())
}

/// Build the disk image, linking the result at `output/aos.raw`.
fn image(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "image";
    let out_link = "output/aos.raw";

    printer.info("Building image...");
    printer.info(&format!("Output: {out_link}"));

    let spinner = printer.activity("building image");
    let store_path = nix
        .build(attr, Some(out_link))
        .with_context(|| "building image")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "store_path": store_path.to_string_lossy(),
        "output": out_link,
    })) {
        return Ok(());
    }

    printer.success(&format!("Built image -> {}", store_path.display()));

    Ok(())
}

/// Evaluate the system configuration and pretty-print it as JSON.
fn eval(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "system.config";

    printer.info("Evaluating system...");

    let spinner = printer.activity("evaluating system");
    let value = nix.eval_json(attr).with_context(|| "evaluating system")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&value) {
        return Ok(());
    }

    // Pretty-print the JSON for human consumption.
    let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value}"));
    printer.plain(&pretty);

    printer.success("Evaluation succeeded");

    Ok(())
}
