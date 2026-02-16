use anyhow::{Context, Result};

use crate::cli::SystemCmd;
use crate::error::AosError;
use crate::nix::NixRunner;
use crate::output::{create_spinner, Printer};

/// Known system variants.
const KNOWN_VARIANTS: &[&str] = &["base", "server", "k8s-worker", "k8s-control-plane"];

pub fn run(nix: &NixRunner, printer: &Printer, cmd: &SystemCmd) -> Result<()> {
    match cmd {
        SystemCmd::Build { variant } => build(nix, printer, variant),
        SystemCmd::Image { variant } => image(nix, printer, variant),
        SystemCmd::Eval { variant } => eval(nix, printer, variant),
    }
}

fn validate_variant(variant: &str) -> Result<()> {
    if !KNOWN_VARIANTS.contains(&variant) {
        return Err(AosError::InvalidArgument {
            message: format!(
                "unknown system variant '{variant}'. Known variants: {}",
                KNOWN_VARIANTS.join(", ")
            ),
        }
        .into());
    }
    Ok(())
}

fn build(nix: &NixRunner, printer: &Printer, variant: &str) -> Result<()> {
    validate_variant(variant)?;

    let attr = format!("systems.{variant}.config.system.build.toplevel");

    printer.info(&format!("Building system '{variant}'..."));

    let spinner = create_spinner(&format!("building system {variant}"));
    let store_path = nix
        .build(&attr, None)
        .with_context(|| format!("building system '{variant}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "variant": variant,
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!(
        "Built system {variant} -> {}",
        store_path.display()
    ));

    Ok(())
}

fn image(nix: &NixRunner, printer: &Printer, variant: &str) -> Result<()> {
    validate_variant(variant)?;

    let attr = format!("images.{variant}");
    let out_link = format!("output/aos-{variant}.raw");

    printer.info(&format!("Building image for '{variant}'..."));
    printer.info(&format!("Output: {out_link}"));

    let spinner = create_spinner(&format!("building image {variant}"));
    let store_path = nix
        .build(&attr, Some(&out_link))
        .with_context(|| format!("building image for '{variant}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "variant": variant,
        "store_path": store_path.to_string_lossy(),
        "output": out_link,
    })) {
        return Ok(());
    }

    printer.success(&format!(
        "Built image {variant} -> {}",
        store_path.display()
    ));

    Ok(())
}

fn eval(nix: &NixRunner, printer: &Printer, variant: &str) -> Result<()> {
    validate_variant(variant)?;

    let attr = format!("systems.{variant}.config");

    printer.info(&format!("Evaluating system '{variant}'..."));

    let spinner = create_spinner(&format!("evaluating {variant}"));
    let value = nix
        .eval_json(&attr)
        .with_context(|| format!("evaluating system '{variant}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&value) {
        return Ok(());
    }

    // Pretty-print the JSON for human consumption.
    let pretty =
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value}"));
    printer.plain(&pretty);

    printer.success(&format!("Evaluation of '{variant}' succeeded"));

    Ok(())
}
