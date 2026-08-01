//! Checks that control-plane crates do not bypass the session/API boundary.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use toml::Value;

#[test]
fn cli_and_daemon_do_not_depend_on_engine_directly() -> Result<(), Box<dyn Error>> {
    let manifests = load_crucible_manifests()?;
    let workspace_dependencies = load_workspace_dependencies()?;
    let findings =
        control_plane_boundary_findings(&manifests, &workspace_dependencies, &CONTROL_PLANE_CRATES);

    assert!(
        findings.is_empty(),
        "control-plane boundary findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn control_plane_boundary_rejects_direct_engine_dependency() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible-cli"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings =
        control_plane_boundary_findings(&manifests, &toml::map::Map::new(), &["crucible-cli"]);

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("direct dependency")),
        "expected direct engine dependency finding, got {findings:?}"
    );

    Ok(())
}

#[test]
fn control_plane_boundary_rejects_target_specific_engine_dependency() -> Result<(), Box<dyn Error>>
{
    let manifest: Value = r#"
        [package]
        name = "crucible-daemon"
        version = "0.1.0"
        edition = "2024"

        [target.'cfg(unix)'.dependencies]
        engine = { package = "crucible", path = "../crucible" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-daemon"), manifest)]);
    let findings =
        control_plane_boundary_findings(&manifests, &toml::map::Map::new(), &["crucible-daemon"]);

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("direct dependency")),
        "expected target-specific engine dependency finding, got {findings:?}"
    );

    Ok(())
}

#[test]
fn control_plane_boundary_rejects_workspace_engine_alias() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible-cli"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        engine = { workspace = true }
    "#
    .parse()?;
    let workspace: Value = r#"
        [workspace.dependencies]
        engine = { package = "crucible", path = "crucible" }
    "#
    .parse()?;
    let workspace_dependencies = workspace
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings =
        control_plane_boundary_findings(&manifests, &workspace_dependencies, &["crucible-cli"]);

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("direct dependency")),
        "expected workspace alias finding, got {findings:?}"
    );

    Ok(())
}

#[test]
fn control_plane_boundary_allows_api_and_session_dependencies() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible-daemon"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        crucible-api = { path = "../crucible-api" }
        session = { package = "crucible-session", path = "../crucible-session" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-daemon"), manifest)]);
    let findings =
        control_plane_boundary_findings(&manifests, &toml::map::Map::new(), &["crucible-daemon"]);

    assert!(findings.is_empty(), "{findings:?}");

    Ok(())
}

const CONTROL_PLANE_CRATES: [&str; 2] = ["crucible-cli", "crucible-daemon"];
const ALLOWED_ENGINE_ENTRYPOINTS: [&str; 2] = ["crucible-api", "crucible-session"];

fn control_plane_boundary_findings(
    manifests: &BTreeMap<String, Value>,
    workspace_dependencies: &toml::map::Map<String, Value>,
    packages: &[&str],
) -> Vec<String> {
    let mut findings = Vec::new();

    for package in packages {
        let manifest = manifests
            .get(*package)
            .unwrap_or_else(|| panic!("missing manifest for `{package}`"));
        for dependency in dependency_specs(manifest, workspace_dependencies) {
            if dependency.package == "crucible" {
                findings.push(format!(
                    "`{package}` has direct dependency `{}` on the engine crate in {}",
                    dependency.key, dependency.scope
                ));
            } else if dependency.package.starts_with("crucible-")
                && !ALLOWED_ENGINE_ENTRYPOINTS.contains(&dependency.package.as_str())
            {
                findings.push(format!(
                    "`{package}` may reach the engine only through crucible-api/crucible-session, found `{}`",
                    dependency.package
                ));
            }
        }
    }

    findings
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DependencySpec {
    key: String,
    package: String,
    scope: String,
}

fn dependency_specs(
    manifest: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<DependencySpec> {
    let mut specs = dependency_table_specs(manifest, "dependencies", workspace_dependencies);

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, value) in targets {
            let scope = format!("target.{target}.dependencies");
            specs.extend(dependency_table_specs(
                value,
                &scope,
                workspace_dependencies,
            ));
        }
    }

    specs
}

fn dependency_table_specs(
    manifest: &Value,
    scope: &str,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<DependencySpec> {
    manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .map(|dependencies| {
            dependencies
                .iter()
                .map(|(key, value)| dependency_spec(key, value, scope, workspace_dependencies))
                .collect()
        })
        .unwrap_or_default()
}

fn dependency_spec(
    key: &str,
    value: &Value,
    scope: &str,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> DependencySpec {
    let package = if value
        .as_table()
        .and_then(|table| table.get("workspace"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        workspace_dependencies
            .get(key)
            .and_then(|workspace_value| workspace_value.as_table())
            .and_then(|table| table.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_owned()
    } else {
        value
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_owned()
    };

    DependencySpec {
        key: key.to_owned(),
        package,
        scope: scope.to_owned(),
    }
}

fn load_workspace_dependencies() -> Result<toml::map::Map<String, Value>, Box<dyn Error>> {
    let workspace_manifest = workspace_root().join("crates/Cargo.toml");
    let manifest: Value = std::fs::read_to_string(&workspace_manifest)?.parse()?;
    Ok(manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default())
}

fn load_crucible_manifests() -> Result<BTreeMap<String, Value>, Box<dyn Error>> {
    let crates_dir = workspace_root().join("crates");
    let mut manifests = BTreeMap::new();

    for entry in std::fs::read_dir(&crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with("crucible") {
            continue;
        }
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }

        let manifest: Value = std::fs::read_to_string(&manifest_path)?.parse()?;
        let package = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{} lacks package.name", manifest_path.display()))?;
        manifests.insert(package.to_owned(), manifest);
    }

    Ok(manifests)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}
