//! `aos show` — display a package's metadata.
//!
//! Evaluates package metadata, the native deployment envelope, and generated
//! module documentation. JSON includes `deployment` and `documentation` beside
//! the ordinary metadata; text summarizes their typed declarations. This local
//! evaluation does not authenticate a publication or inspect live execution.

use anyhow::{Context, Result};
use aos_doc_model::runtime::RuntimeDocument;
use aos_package::deployment::model::Envelope;

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos show <package>` — display package metadata.
///
/// # Errors
///
/// Returns an error if evaluating package metadata or native declarations fails,
/// their identities disagree, or the package does not exist.
pub fn run(nix: &NixRunner, printer: &Printer, package: &str) -> Result<()> {
    let attr = format!("pkgs.{package}.meta");
    let package_name =
        serde_json::to_string(package).context("serializing package name for Nix expression")?;
    let root = serde_json::to_string(&nix.root().to_string_lossy())
        .context("serializing repository path for Nix expression")?;
    let native_views_expr = format!(
        r#"let
          root = import (builtins.toPath {root}) {{}};
          pkg = builtins.getAttr {package_name} root.pkgs;
        in {{ inherit (pkg) deployment documentation; }}"#
    );

    printer.info(&format!("Fetching metadata for '{package}'..."));

    let spinner = printer.activity(&format!("evaluating {package}.meta"));
    let mut meta = nix
        .eval_json(&attr)
        .with_context(|| format!("evaluating metadata for '{package}'"))?;
    let (envelope, documentation) = decode_native_views(
        nix.eval_expr_json(&native_views_expr)
            .with_context(|| format!("evaluating native package declarations for '{package}'"))?,
    )?;
    spinner.finish_and_clear();

    let object = meta
        .as_object_mut()
        .context("package metadata is not an object")?;
    object.insert("deployment".into(), serde_json::to_value(&envelope)?);
    object.insert("documentation".into(), documentation.value().clone());

    if printer.json_if_active(&meta) {
        return Ok(());
    }

    // Pretty-print selected fields.
    printer.header(&format!("Package: {package}"));

    printer.kv("Name", &envelope.package.name);
    printer.kv("Version", &envelope.package.version);
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
    printer.kv("Target platform", &envelope.system);
    printer.kv("Payload", &envelope.package.path);
    printer.kv(
        "Runtime dependencies",
        &envelope.runtime_dependencies.len().to_string(),
    );
    printer.kv(
        "Module dependencies",
        &envelope.module_dependencies.len().to_string(),
    );
    if let Some(module) = &envelope.module {
        printer.kv("Module source", &module.source);
    }
    if let Some(reference) = documentation.reference() {
        let operations = reference
            .abilities
            .values()
            .map(|operations| operations.len())
            .sum::<usize>();
        let handlers = reference
            .abilities
            .values()
            .flat_map(|operations| operations.values())
            .filter(|operation| operation.handler_available)
            .count();
        printer.kv(
            "Generated options",
            &documentation
                .options()
                .iter()
                .filter(|option| option.visibility != aos_doc_model::Visibility::Hidden)
                .count()
                .to_string(),
        );
        printer.kv("Declared operations", &operations.to_string());
        printer.kv("Available handlers", &handlers.to_string());
    }

    Ok(())
}

/// Checks the evaluator's native views through their shared format readers.
fn decode_native_views(value: serde_json::Value) -> Result<(Envelope, RuntimeDocument)> {
    let envelope = value
        .get("deployment")
        .context("package has no native deployment envelope")?;
    let envelope = Envelope::decode(&serde_json::to_vec(envelope)?)?;
    let documentation = value
        .get("documentation")
        .context("package has no native module documentation")?;
    let documentation = RuntimeDocument::from_json(&serde_json::to_vec(documentation)?)?;
    documentation.verify_package_identity(
        &envelope.package.name,
        &envelope.package.version,
        &envelope.system,
    )?;
    Ok((envelope, documentation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn views() -> serde_json::Value {
        let root = "/nix/store/00000000000000000000000000000000-example";
        json!({
            "deployment": {"schema":"aos.package.deployment","system":"x86_64-linux",
                "package":{"name":"example","version":"1","path":root,"outputs":{"out":root},"mainProgram":null},
                "module":null,"runtimeDependencies":{},"moduleDependencies":[]},
            "documentation":{"schema":"aos.module.documentation","scope":["package","example"],
                "system":"x86_64-linux","packages":[{"name":"example","version":"1"}],
                "options":[],"abilities":{}}
        })
    }

    #[test]
    fn native_views_preserve_available_payload_and_declaration_identity() {
        let value = views();
        let (envelope, documentation) = decode_native_views(value.clone()).unwrap();
        assert_eq!(envelope.package.outputs["out"], envelope.package.path);
        assert_eq!(documentation.value(), &value["documentation"]);
        assert!(envelope.module.is_none());
    }

    #[test]
    fn native_views_reject_documentation_from_another_package_or_platform() {
        for (field, replacement) in [
            ("system", json!("aarch64-linux")),
            ("scope", json!(["package", "other"])),
        ] {
            let mut value = views();
            value["documentation"][field] = replacement;
            assert!(decode_native_views(value).is_err());
        }
    }

    #[test]
    fn native_views_reject_retired_static_contract_projection() {
        assert!(decode_native_views(json!({"abilityProjection":{"interfaces":[]}})).is_err());
    }
}
