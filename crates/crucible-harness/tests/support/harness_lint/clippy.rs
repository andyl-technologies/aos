//! Shared support for `clippy`.

use super::*;

pub(super) fn clippy_tier_failures(
    workspace_manifest: &str,
    clippy_config: &str,
    package_manifests: &[(&str, String)],
    crucible_package: &str,
) -> Vec<String> {
    let mut findings = Vec::new();

    if let Some(workspace_doc) = parse_toml("crates/Cargo.toml", workspace_manifest, &mut findings)
    {
        for lint in CLIPPY_DENY_LINTS {
            if toml_string_at(&workspace_doc, &["workspace", "lints", "clippy", lint])
                != Some("deny")
            {
                findings.push(format!(
                    "crates/Cargo.toml: missing workspace clippy deny `{lint} = \"deny\"`"
                ));
            }
        }
    }

    if let Some(clippy_doc) = parse_toml("crates/clippy.toml", clippy_config, &mut findings) {
        for method in CLIPPY_DISALLOWED_METHODS {
            if !toml_array_has_path(&clippy_doc, "disallowed-methods", method) {
                findings.push(format!(
                    "crates/clippy.toml: missing disallowed method `{method}`"
                ));
            }
        }

        for disallowed_type in CLIPPY_DISALLOWED_TYPES {
            if !toml_array_has_path(&clippy_doc, "disallowed-types", disallowed_type) {
                findings.push(format!(
                    "crates/clippy.toml: missing disallowed type `{disallowed_type}`"
                ));
            }
        }
    }

    for (package, manifest) in package_manifests {
        match parse_toml(&format!("{package}/Cargo.toml"), manifest, &mut findings) {
            Some(manifest_doc)
                if toml_bool_at(&manifest_doc, &["lints", "workspace"]) == Some(true) => {}
            Some(_) => findings.push(format!(
                "{package}/Cargo.toml: missing workspace lint inheritance"
            )),
            None => {}
        }
    }

    for required in [
        "cargo clippy",
        "--all-targets",
        "rust.dev",
        "-D warnings",
        "${workspaceCargoFlags}",
    ] {
        if !crucible_package.contains(required) {
            findings.push(format!(
                "pkgs/tools/crucible/crucible.nix: missing clippy gate wiring `{required}`"
            ));
        }
    }

    findings
}

pub(super) fn parse_toml(
    label: &str,
    content: &str,
    findings: &mut Vec<String>,
) -> Option<toml::Value> {
    match content.parse::<toml::Value>() {
        Ok(value) => Some(value),
        Err(error) => {
            findings.push(format!("{label}: invalid TOML: {error}"));
            None
        }
    }
}

pub(super) fn toml_string_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub(super) fn toml_bool_at(value: &toml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

pub(super) fn toml_array_has_path(value: &toml::Value, key: &str, required_path: &str) -> bool {
    let Some(entries) = value.get(key).and_then(toml::Value::as_array) else {
        return false;
    };

    entries
        .iter()
        .any(|entry| entry.get("path").and_then(toml::Value::as_str) == Some(required_path))
}
