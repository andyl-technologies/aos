use anyhow::{Context, Result};

use crate::cli::SystemCmd;
use aos_core::nix::NixRunner;
use aos_core::output::{create_spinner, Printer};

pub fn run(nix: &NixRunner, printer: &Printer, cmd: &SystemCmd) -> Result<()> {
    match cmd {
        SystemCmd::Build => build(nix, printer),
        SystemCmd::Image => image(nix, printer),
        SystemCmd::Eval => eval(nix, printer),
    }
}

fn build(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "system.config.system.build.toplevel";

    printer.info("Building system...");

    let spinner = create_spinner("building system");
    let store_path = nix
        .build(attr, None)
        .with_context(|| "building system")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!(
        "Built system -> {}",
        store_path.display()
    ));

    Ok(())
}

fn image(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "image";
    let out_link = "output/aos.raw";

    printer.info("Building image...");
    printer.info(&format!("Output: {out_link}"));

    let spinner = create_spinner("building image");
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

    printer.success(&format!(
        "Built image -> {}",
        store_path.display()
    ));

    Ok(())
}

fn eval(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let attr = "system.config";

    printer.info("Evaluating system...");

    let spinner = create_spinner("evaluating system");
    let value = nix
        .eval_json(attr)
        .with_context(|| "evaluating system")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&value) {
        return Ok(());
    }

    // Pretty-print the JSON for human consumption.
    let pretty =
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value}"));
    printer.plain(&pretty);

    printer.success("Evaluation succeeded");

    Ok(())
}
