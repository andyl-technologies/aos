use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::{Printer, create_spinner};

/// `aos show <package>` — display package metadata.
pub fn run(nix: &NixRunner, printer: &Printer, package: &str) -> Result<()> {
    let attr = format!("pkgs.{package}.meta");

    printer.info(&format!("Fetching metadata for '{package}'..."));

    let spinner = create_spinner(&format!("evaluating {package}.meta"));
    let meta = nix
        .eval_json(&attr)
        .with_context(|| format!("evaluating metadata for '{package}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&meta) {
        return Ok(());
    }

    // Pretty-print selected fields.
    printer.header(&format!("Package: {package}"));

    if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
        printer.kv("Name", name);
    }
    if let Some(version) = meta.get("version").and_then(|v| v.as_str()) {
        printer.kv("Version", version);
    }
    if let Some(desc) = meta.get("description").and_then(|v| v.as_str()) {
        printer.kv("Description", desc);
    }
    if let Some(license) = meta.get("license") {
        let license_str = if let Some(s) = license.as_str() {
            s.to_string()
        } else if let Some(obj) = license.as_object() {
            obj.get("spdxId")
                .or_else(|| obj.get("shortName"))
                .or_else(|| obj.get("fullName"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            format!("{license}")
        };
        printer.kv("License", &license_str);
    }
    if let Some(homepage) = meta.get("homepage").and_then(|v| v.as_str()) {
        printer.kv("Homepage", homepage);
    }
    if let Some(platforms) = meta.get("platforms").and_then(|v| v.as_array()) {
        let list: Vec<&str> = platforms.iter().filter_map(|v| v.as_str()).collect();
        if !list.is_empty() {
            printer.kv("Platforms", &list.join(", "));
        }
    }
    if let Some(maintainers) = meta.get("maintainers").and_then(|v| v.as_array()) {
        let names: Vec<String> = maintainers
            .iter()
            .filter_map(|m| {
                m.as_str()
                    .map(String::from)
                    .or_else(|| m.get("name").and_then(|n| n.as_str()).map(String::from))
            })
            .collect();
        if !names.is_empty() {
            printer.kv("Maintainers", &names.join(", "));
        }
    }

    Ok(())
}
