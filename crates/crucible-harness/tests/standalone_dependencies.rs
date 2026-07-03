//! Checks that Crucible stays standalone from RFC-0007 crates.
//!
//! RFC-0010 file 27 requires all content-addressing primitives needed today to
//! live in `crucible-sim`. This lint rejects direct or workspace-inherited
//! dependencies on `ratchet-*` and `aos-nix-*` crates, and verifies the named
//! future integration seam remains documented in the simulation crate.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

const FORBIDDEN_DEPENDENCY_PREFIXES: [&str; 2] = ["ratchet-", "aos-nix-"];
const FORBIDDEN_DEPENDENCY_NAMES: [&str; 2] = ["ratchet", "aos-nix"];
const SEAM_MARKER: &str = "FUTURE_RATCHET_INTEGRATION_SEAM";
const SEAM_VALUE: &str = "crucible-sim::content-addressing";

#[test]
fn crucible_crates_do_not_depend_on_ratchet_or_aos_nix() -> Result<(), Box<dyn Error>> {
    let manifests = load_crucible_manifests()?;
    let workspace_dependencies = load_workspace_dependencies()?;
    let findings = forbidden_dependency_findings(&manifests, &workspace_dependencies);

    assert!(
        findings.is_empty(),
        "Crucible standalone dependency findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn crucible_sim_marks_the_future_ratchet_integration_seam() -> Result<(), Box<dyn Error>> {
    let sim_root = workspace_root().join("crates/crucible-sim/src/lib.rs");
    let content = fs::read_to_string(&sim_root)?;

    assert!(
        content.contains(SEAM_MARKER),
        "{} must expose `{SEAM_MARKER}`",
        display_repo_path(&sim_root)
    );
    assert!(
        content.contains(SEAM_VALUE),
        "{} must name the content-addressing seam value `{SEAM_VALUE}`",
        display_repo_path(&sim_root)
    );
    assert!(
        content.contains("no Crucible crate may depend on `ratchet-*` or `aos-nix-*`"),
        "{} must document the standalone dependency rule near the seam marker",
        display_repo_path(&sim_root)
    );

    Ok(())
}

#[test]
fn standalone_dependency_rules_reject_direct_workspace_and_target_edges()
-> Result<(), Box<dyn Error>> {
    let direct_ratchet: Value = r#"
        [package]
        name = "crucible-sim"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        ratchet = "0.1"
    "#
    .parse()?;
    let direct_findings = forbidden_dependency_findings(
        &BTreeMap::from([(String::from("crucible-sim"), direct_ratchet)]),
        &toml::map::Map::new(),
    );
    assert!(
        contains_finding(&direct_findings, "ratchet"),
        "direct exact ratchet dependency should be rejected: {direct_findings:?}"
    );

    let alias_aos_nix: Value = r#"
        [package]
        name = "crucible"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        graph = { package = "aos-nix-graph", path = "../aos-nix-graph" }
    "#
    .parse()?;
    let alias_findings = forbidden_dependency_findings(
        &BTreeMap::from([(String::from("crucible"), alias_aos_nix)]),
        &toml::map::Map::new(),
    );
    assert!(
        contains_finding(&alias_findings, "aos-nix-graph"),
        "package-renamed aos-nix dependency should be rejected: {alias_findings:?}"
    );

    let workspace_inherited: Value = r#"
        [package]
        name = "crucible-api"
        version = "0.1.0"
        edition = "2024"

        [dev-dependencies]
        ratchet-store = { workspace = true }
    "#
    .parse()?;
    let workspace_dependencies: toml::map::Map<String, Value> = r#"
        [workspace.dependencies]
        ratchet-store = { package = "ratchet-cache", path = "ratchet-cache" }
    "#
    .parse::<Value>()?
    .get("workspace")
    .and_then(|workspace| workspace.get("dependencies"))
    .and_then(Value::as_table)
    .cloned()
    .unwrap_or_default();
    let workspace_findings = forbidden_dependency_findings(
        &BTreeMap::from([(String::from("crucible-api"), workspace_inherited)]),
        &workspace_dependencies,
    );
    assert!(
        contains_finding(&workspace_findings, "ratchet-cache"),
        "workspace-inherited ratchet dependency should be rejected: {workspace_findings:?}"
    );

    let target_specific: Value = r#"
        [package]
        name = "crucible-qemu"
        version = "0.1.0"
        edition = "2024"

        [target.'cfg(unix)'.build-dependencies]
        helper = { package = "aos-nix-helper", path = "../aos-nix-helper" }
    "#
    .parse()?;
    let target_findings = forbidden_dependency_findings(
        &BTreeMap::from([(String::from("crucible-qemu"), target_specific)]),
        &toml::map::Map::new(),
    );
    assert!(
        contains_finding(&target_findings, "target.cfg(unix).build-dependencies"),
        "target build-dependency should be rejected: {target_findings:?}"
    );

    Ok(())
}

fn forbidden_dependency_findings(
    manifests: &BTreeMap<String, Value>,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<String> {
    let mut findings = Vec::new();

    for (package, manifest) in manifests {
        for dependency in dependency_specs(manifest, workspace_dependencies) {
            if forbidden_dependency_name(&dependency.package)
                || forbidden_dependency_name(&dependency.key)
            {
                findings.push(format!(
                    "`{package}` has forbidden dependency `{}` resolved as `{}` in {}",
                    dependency.key, dependency.package, dependency.scope
                ));
            }
        }
    }

    findings
}

fn forbidden_dependency_name(name: &str) -> bool {
    FORBIDDEN_DEPENDENCY_NAMES.contains(&name)
        || FORBIDDEN_DEPENDENCY_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn dependency_specs(
    manifest: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> Vec<DependencySpec> {
    let mut specs = Vec::new();
    specs.extend(dependency_table_specs(
        manifest,
        "dependencies",
        workspace_dependencies,
    ));
    specs.extend(dependency_table_specs(
        manifest,
        "dev-dependencies",
        workspace_dependencies,
    ));
    specs.extend(dependency_table_specs(
        manifest,
        "build-dependencies",
        workspace_dependencies,
    ));

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, value) in targets {
            for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
                specs.extend(dependency_table_specs(
                    value,
                    &format!("target.{target}.{table}"),
                    workspace_dependencies,
                ));
            }
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
        .get(scope.rsplit('.').next().unwrap_or(scope))
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
            .and_then(Value::as_table)
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct DependencySpec {
    key: String,
    package: String,
    scope: String,
}

fn load_workspace_dependencies() -> Result<toml::map::Map<String, Value>, Box<dyn Error>> {
    let workspace_manifest = workspace_root().join("crates/Cargo.toml");
    let manifest: Value = fs::read_to_string(&workspace_manifest)?.parse()?;
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

    for entry in fs::read_dir(&crates_dir)? {
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

        let manifest: Value = fs::read_to_string(&manifest_path)?.parse()?;
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

fn display_repo_path(path: &Path) -> String {
    let root = workspace_root();
    match path.strip_prefix(&root) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn contains_finding(findings: &[String], needle: &str) -> bool {
    findings.iter().any(|finding| finding.contains(needle))
}
