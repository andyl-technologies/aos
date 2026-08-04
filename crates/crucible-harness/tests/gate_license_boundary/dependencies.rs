//! Checks production Cargo dependency edges across the license boundary.
//!
//! The scanner covers normal and build dependencies at the manifest root and
//! beneath every target-specific table. Development dependencies are excluded
//! because they are not linked into distributed production artifacts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;

use toml::Value;

use super::{
    APACHE_LICENSE, PLUGIN_LICENSE, PLUGIN_PACKAGE, declared_package_license, workspace_crates_dir,
};

#[test]
fn non_gpl_crates_cannot_depend_on_qemu_side_implementation_crates() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let workspace: Value = fs::read_to_string(crates.join("Cargo.toml"))?.parse()?;
    let members = workspace["workspace"]["members"]
        .as_array()
        .ok_or("workspace.members must be an array")?;
    let workspace_dependencies = workspace["workspace"]["dependencies"]
        .as_table()
        .ok_or("workspace.dependencies must be a table")?;
    let mut workspace_packages = Vec::new();
    let mut workspace_licenses = BTreeMap::new();

    for member in members {
        let member_path = member.as_str().ok_or("workspace member must be a string")?;
        let manifest: Value =
            fs::read_to_string(crates.join(member_path).join("Cargo.toml"))?.parse()?;
        let package_table = manifest["package"]
            .as_table()
            .ok_or("package metadata must be a table")?;
        let package_name = package_table["name"]
            .as_str()
            .ok_or("package.name must be a string")?;
        let license = declared_package_license(package_table, APACHE_LICENSE)
            .ok_or("package license must be explicit or inherited")?;
        workspace_licenses.insert(package_name.to_owned(), license.clone());
        workspace_packages.push((member_path.to_owned(), package_name.to_owned(), license));
    }

    let mut failures = Vec::new();
    for (member_path, package_name, license) in workspace_packages {
        if license == PLUGIN_LICENSE {
            continue;
        }
        let manifest: Value =
            fs::read_to_string(crates.join(member_path).join("Cargo.toml"))?.parse()?;
        collect_forbidden_qemu_dependencies(
            &package_name,
            &manifest,
            workspace_dependencies,
            &workspace_licenses,
            &mut failures,
        )?;
    }

    assert!(
        failures.is_empty(),
        "non-GPL crate dependency boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn dependency_boundary_scans_normal_build_and_target_tables() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [dependencies]
        direct = { package = "crucible-qemu-plugin", version = "1" }

        [build-dependencies]
        build = { package = "crucible-qemu-plugin-helper", version = "1" }

        [target.'cfg(target_os = "linux")'.dependencies]
        target-normal = { package = "vendor-qemu-plugin", version = "1" }

        [target.'cfg(unix)'.build-dependencies]
        target-build = { package = "crucible-qemu-side-codegen", version = "1" }

        [dev-dependencies]
        allowed-test-fixture = { package = "crucible-qemu-plugin", version = "1" }
    "#
    .parse()?;
    let workspace_dependencies = toml::map::Map::new();
    let workspace_licenses =
        BTreeMap::from([(String::from(PLUGIN_PACKAGE), String::from(PLUGIN_LICENSE))]);
    let mut failures = Vec::new();

    collect_forbidden_qemu_dependencies(
        "apache-fixture",
        &manifest,
        &workspace_dependencies,
        &workspace_licenses,
        &mut failures,
    )?;

    assert_eq!(
        failures.len(),
        4,
        "every production dependency table is scanned"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("dependencies"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("build-dependencies"))
    );
    assert!(failures.iter().any(|failure| failure.contains("target.")));
    assert!(
        failures
            .iter()
            .all(|failure| !failure.contains("allowed-test-fixture")),
        "dev-dependencies are outside the production package boundary"
    );
    Ok(())
}

fn collect_forbidden_qemu_dependencies(
    package: &str,
    manifest: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
    workspace_licenses: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    visit_production_dependency_tables(manifest, &mut |table_name, dependencies| {
        for (alias, dependency) in dependencies {
            let package_name =
                resolved_dependency_package(alias, dependency, workspace_dependencies);
            let dependency_license = workspace_licenses.get(package_name);
            if dependency_license.map(String::as_str) == Some(PLUGIN_LICENSE)
                || is_qemu_side_implementation_name(package_name)
            {
                failures.push(format!(
                    "{package}: production {table_name} entry `{alias}` resolves to forbidden QEMU-side package `{package_name}`"
                ));
            }
        }
    })?;
    Ok(())
}

pub(super) fn visit_production_dependency_tables(
    manifest: &Value,
    visitor: &mut impl FnMut(&str, &toml::map::Map<String, Value>),
) -> Result<(), Box<dyn Error>> {
    let root = manifest
        .as_table()
        .ok_or("Cargo manifest must be a table")?;
    for table_name in ["dependencies", "build-dependencies"] {
        if let Some(dependencies) = root.get(table_name).and_then(Value::as_table) {
            visitor(table_name, dependencies);
        }
    }
    if let Some(targets) = root.get("target").and_then(Value::as_table) {
        for (target, target_value) in targets {
            let target_table = target_value
                .as_table()
                .ok_or("Cargo target dependency section must be a table")?;
            for dependency_kind in ["dependencies", "build-dependencies"] {
                if let Some(dependencies) =
                    target_table.get(dependency_kind).and_then(Value::as_table)
                {
                    let label = format!("target.{target}.{dependency_kind}");
                    visitor(&label, dependencies);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn resolved_dependency_package<'a>(
    alias: &'a str,
    dependency: &'a Value,
    workspace_dependencies: &'a toml::map::Map<String, Value>,
) -> &'a str {
    let specification = if dependency.get("workspace").and_then(Value::as_bool) == Some(true) {
        workspace_dependencies.get(alias).unwrap_or(dependency)
    } else {
        dependency
    };
    specification
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or(alias)
}

fn is_qemu_side_implementation_name(package: &str) -> bool {
    package == PLUGIN_PACKAGE
        || package.starts_with("crucible-qemu-plugin-")
        || package.ends_with("-qemu-plugin")
        || package.contains("-qemu-side-")
        || package.starts_with("qemu-crucible-internal-")
}
