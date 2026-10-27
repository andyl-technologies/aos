//! Checks that public CLI code does not bypass the host composition boundary.

#[path = "support/workspace.rs"]
mod workspace;

#[path = "support/architecture.rs"]
mod architecture;

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

use toml::Value;

#[test]
fn cli_uses_only_declared_host_composition_dependencies() -> Result<(), Box<dyn Error>> {
    let findings = if let Some(graph) = architecture::load()? {
        let dependencies = graph
            .production_dependencies("crucible-cli")?
            .iter()
            .map(|package| DependencySpec {
                key: package.clone(),
                package: package.clone(),
                scope: String::from("declared Bazel production graph"),
            })
            .collect();
        control_plane_dependency_findings(dependencies)
    } else {
        let manifests = load_crucible_manifests()?;
        let workspace_dependencies = load_workspace_dependencies()?;
        control_plane_boundary_findings(&manifests, &workspace_dependencies)
    };

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
        engine = { package = "crucible-engine", path = "../crucible-engine" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings = control_plane_boundary_findings(&manifests, &toml::map::Map::new());

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
        name = "crucible-cli"
        version = "0.1.0"
        edition = "2024"

        [target.'cfg(unix)'.dependencies]
        engine = { package = "crucible-engine", path = "../crucible-engine" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings = control_plane_boundary_findings(&manifests, &toml::map::Map::new());

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
        engine = { package = "crucible-engine", path = "crucible-engine" }
    "#
    .parse()?;
    let workspace_dependencies = workspace
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings = control_plane_boundary_findings(&manifests, &workspace_dependencies);

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
        name = "crucible-cli"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        crucible-control-api = { path = "../crucible-control-api" }
        session = { package = "crucible-session", path = "../crucible-session" }
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible-cli"), manifest)]);
    let findings = control_plane_boundary_findings(&manifests, &toml::map::Map::new());

    assert!(findings.is_empty(), "{findings:?}");

    Ok(())
}

const CLI_ALLOWED_CRUCIBLE_DEPENDENCIES: [&str; 6] = [
    "crucible-control-api",
    "crucible-control-client",
    "crucible-control-server",
    "crucible-campaign",
    "crucible-daemon",
    "crucible-session",
];

#[test]
fn architecture_metadata_preserves_declared_dependency_names() -> Result<(), Box<dyn Error>> {
    let graph = architecture::parse(&architecture_fixture().to_string())?;
    let dependencies = graph.production_dependencies("crucible-cli")?;

    assert_eq!(
        dependencies,
        &std::collections::BTreeSet::from([String::from("crucible-engine")])
    );
    assert!(graph.production_dependencies("absent-package").is_err());

    Ok(())
}

#[test]
fn architecture_metadata_rejects_incomplete_or_inconsistent_graphs() {
    let original = architecture_fixture();
    let mut fixtures = Vec::new();

    let mut duplicate = original.clone();
    duplicate["packages"]
        .as_array_mut()
        .unwrap()
        .push(original["packages"][0].clone());
    fixtures.push(("duplicate package", duplicate));

    let mut escape = original.clone();
    escape["packages"][0]["directory"] = serde_json::json!("crates/../outside");
    fixtures.push(("escaped source ownership", escape));

    let mut inconsistent = original.clone();
    inconsistent["packages"][0]["production_dependencies"] = serde_json::json!([]);
    fixtures.push(("mismatched target edges", inconsistent));

    let mut missing = original.clone();
    missing["target_dependencies"] = serde_json::json!({});
    fixtures.push(("missing target records", missing));

    let mut unmodeled = original.clone();
    unmodeled["packages"][0]["production_dependencies"] = serde_json::Value::Null;
    fixtures.push(("missing production graph", unmodeled));

    let mut identity = original.clone();
    identity["query_sha256"] = serde_json::json!("not-a-query-digest");
    fixtures.push(("invalid query identity", identity));

    let mut selection = original;
    selection["selection"] = serde_json::json!("one configured platform only");
    fixtures.push(("incomplete platform selection", selection));

    for (name, fixture) in fixtures {
        assert!(
            architecture::parse(&fixture.to_string()).is_err(),
            "accepted {name}"
        );
    }
}

fn architecture_fixture() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "selection": "union of all declared production platform/feature branches",
        "query_sha256": "a".repeat(64),
        "packages": [{
            "name": "crucible-cli",
            "directory": "crates/crucible/crucible-cli",
            "production_targets": ["//crates/crucible/crucible-cli:crucible"],
            "production_dependencies": ["crucible-engine"],
        }],
        "target_dependencies": {
            "//crates/crucible/crucible-cli:crucible": [{"packages": ["crucible-engine"]}],
        },
    })
}

fn control_plane_boundary_findings(
    manifests: &BTreeMap<String, Value>,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<String> {
    let Some(manifest) = manifests.get("crucible-cli") else {
        return Vec::new();
    };
    control_plane_dependency_findings(dependency_specs(manifest, workspace_dependencies))
}

fn control_plane_dependency_findings(dependencies: Vec<DependencySpec>) -> Vec<String> {
    let mut findings = Vec::new();

    for dependency in dependencies {
        if dependency.package == "crucible-engine" {
            findings.push(format!(
                "`crucible-cli` has direct dependency `{}` on the engine crate in {}",
                dependency.key, dependency.scope
            ));
        } else if dependency.package.starts_with("crucible-")
            && !CLI_ALLOWED_CRUCIBLE_DEPENDENCIES.contains(&dependency.package.as_str())
        {
            findings.push(format!(
                "`crucible-cli` may reach lower layers only through the API, session, campaign, or daemon composition crates, found `{}`",
                dependency.package
            ));
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

    for entry in workspace::package_entries(&crates_dir)? {
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
    workspace::repository_root()
}
