//! `aos show` — display a package's metadata.
//!
//! Evaluates `pkgs.<package>.meta` and, when the expose manifest is complete at
//! evaluation time, the package expose manifest passthru data. It pretty-prints
//! common package fields plus the RFC-0001 expose target, confinement label,
//! and permission summary. With `--json`, expose packages include an
//! `exposeManifest` field next to the raw meta attrset.

use anyhow::{Context, Result};

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos show <package>` — display package metadata.
///
/// # Errors
///
/// Returns an error if evaluating the package's `meta` attribute fails
/// (e.g. the package does not exist).
pub fn run(nix: &NixRunner, printer: &Printer, package: &str) -> Result<()> {
    let attr = format!("pkgs.{package}.meta");
    let package_name =
        serde_json::to_string(package).context("serializing package name for Nix expression")?;
    let expose_manifest_expr = format!(
        "let root = import {}/default.nix {{}}; pkg = builtins.getAttr {} root.pkgs; in if pkg ? expose then pkg.expose.passthru.manifest else null",
        nix.root().display(),
        package_name
    );

    printer.info(&format!("Fetching metadata for '{package}'..."));

    let spinner = printer.activity(&format!("evaluating {package}.meta"));
    let mut meta = nix
        .eval_json(&attr)
        .with_context(|| format!("evaluating metadata for '{package}'"))?;
    let expose_manifest = match nix
        .eval_expr_json(&expose_manifest_expr)
        .with_context(|| format!("evaluating expose manifest for '{package}'"))?
    {
        serde_json::Value::Null => None,
        value => Some(value),
    };
    spinner.finish_and_clear();

    if let (Some(object), Some(manifest)) = (meta.as_object_mut(), expose_manifest.as_ref()) {
        object.insert("exposeManifest".to_string(), manifest.clone());
    }

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
    if let Some(manifest) = expose_manifest.as_ref() {
        if let Some(target) = manifest
            .pointer("/expose/target")
            .and_then(|value| value.as_str())
        {
            printer.kv("Expose target", target);
        }
        if let Some(label) = manifest
            .pointer("/confinement/label")
            .and_then(|value| value.as_str())
        {
            printer.kv("Confinement", label);
        }
        if let Some(permissions) = manifest.get("permissions") {
            let rendered =
                serde_json::to_string(permissions).context("serializing expose permissions")?;
            printer.kv("Permissions", &rendered);
        }
    }

    Ok(())
}
