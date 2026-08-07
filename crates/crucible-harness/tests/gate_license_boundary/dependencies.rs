//! Checks production Cargo dependency edges and licenses across the boundary.
//!
//! The scanner covers normal and build dependencies at the manifest root and
//! beneath every target-specific table. Development dependencies are excluded
//! because they are not linked into distributed production artifacts. The
//! resolved production graph is also checked for an explicitly approved
//! GPL-2.0-compatible license choice on every external package.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::process::Command;

use serde_json::Value as JsonValue;
use toml::Value;

use super::{
    APACHE_LICENSE, DEBUG_GATEWAY_PACKAGE, PLUGIN_LICENSE, PLUGIN_PACKAGE,
    declared_package_license, workspace_crates_dir,
};

pub(super) fn forbidden_qemu_abi_surfaces(source: &str) -> impl Iterator<Item = &'static str> {
    [
        "extern \"C\" fn qemu_plugin_",
        "qemu-plugin.h",
        "libloading::Library",
        "libc::dlopen(",
        "::dlopen(",
    ]
    .into_iter()
    .filter(|forbidden| source.contains(forbidden))
}

#[test]
fn boundary_crate_source_scanner_rejects_qemu_headers_and_callbacks() {
    let leaking_fixture = r#"
        // A dual-licensed boundary crate must never include qemu-plugin.h.
        extern "C" fn qemu_plugin_boundary_callback() {}
    "#;
    let failures: Vec<_> = forbidden_qemu_abi_surfaces(leaking_fixture).collect();
    assert!(failures.contains(&"qemu-plugin.h"));
    assert!(failures.contains(&"extern \"C\" fn qemu_plugin_"));
    assert!(
        forbidden_qemu_abi_surfaces("qemu-neutral wire protocol")
            .next()
            .is_none()
    );
}

#[test]
fn plugin_distributed_dependency_graph_has_gpl2_compatible_license_choices()
-> Result<(), Box<dyn Error>> {
    let metadata = cargo_metadata()?;
    let failures = resolved_production_graph_failures(
        &metadata,
        PLUGIN_PACKAGE,
        &[PLUGIN_PACKAGE, "crucible-protocol", "crucible-shmem"],
        gpl2_compatible_external_license,
        "plugin",
    )?;

    assert!(
        failures.is_empty(),
        "plugin dependency license/boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn debug_gateway_distributed_dependency_graph_has_gpl2_compatible_license_choices()
-> Result<(), Box<dyn Error>> {
    let metadata = cargo_metadata()?;
    let failures = resolved_production_graph_failures(
        &metadata,
        DEBUG_GATEWAY_PACKAGE,
        &[DEBUG_GATEWAY_PACKAGE, "crucible-protocol"],
        gpl2_compatible_external_license,
        "debug gateway",
    )?;

    assert!(
        failures.is_empty(),
        "debug gateway dependency license/boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn permissive_boundary_dependency_graphs_remain_implementation_neutral()
-> Result<(), Box<dyn Error>> {
    let metadata = cargo_metadata()?;
    let mut failures = Vec::new();
    for root in ["crucible-protocol", "crucible-shmem"] {
        failures.extend(resolved_production_graph_failures(
            &metadata,
            root,
            &["crucible-protocol", "crucible-shmem"],
            permissive_external_license,
            root,
        )?);
    }
    assert!(
        failures.is_empty(),
        "permissive boundary dependency drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

fn cargo_metadata() -> Result<JsonValue, Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(&crates)
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed while validating dependency licenses:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn resolved_production_graph_failures(
    metadata: &JsonValue,
    root_name: &str,
    allowed_local_packages: &[&str],
    external_license_allowed: fn(&str) -> bool,
    context: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata packages must be an array")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata resolve.nodes must be an array")?;
    let root_id = packages
        .iter()
        .find(|package| package["name"].as_str() == Some(root_name))
        .and_then(|package| package["id"].as_str())
        .ok_or("cargo metadata lacks dependency graph root")?;

    let nodes_by_id: BTreeMap<&str, &JsonValue> = nodes
        .iter()
        .filter_map(|node| node["id"].as_str().map(|id| (id, node)))
        .collect();
    let packages_by_id: BTreeMap<&str, &JsonValue> = packages
        .iter()
        .filter_map(|package| package["id"].as_str().map(|id| (id, package)))
        .collect();
    let mut pending = vec![root_id];
    let mut reachable = BTreeSet::new();

    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let node = nodes_by_id
            .get(id)
            .ok_or("cargo metadata resolve node lacks package metadata")?;
        let dependencies = node["deps"]
            .as_array()
            .ok_or("cargo metadata node.deps must be an array")?;
        for dependency in dependencies {
            let kinds = dependency["dep_kinds"]
                .as_array()
                .ok_or("cargo metadata dep_kinds must be an array")?;
            let is_production = kinds.is_empty()
                || kinds
                    .iter()
                    .any(|kind| kind["kind"].as_str() != Some("dev"));
            if is_production {
                pending.push(
                    dependency["pkg"]
                        .as_str()
                        .ok_or("cargo metadata dependency lacks package id")?,
                );
            }
        }
    }

    let mut failures = Vec::new();
    for id in reachable {
        let package = packages_by_id
            .get(id)
            .ok_or("reachable cargo package lacks metadata")?;
        let name = package["name"].as_str().ok_or("package lacks name")?;
        let version = package["version"].as_str().ok_or("package lacks version")?;
        let license = package["license"].as_str().unwrap_or("<missing>");
        if package["source"].is_null() {
            if !allowed_local_packages.contains(&name) {
                failures.push(format!(
                    "{context}: reachable local package `{name}` is not an approved boundary dependency"
                ));
            } else if name != root_name && license != super::BOUNDARY_LICENSE {
                failures.push(format!(
                    "{context}: local boundary package `{name}` must declare `{}`, found `{license}`",
                    super::BOUNDARY_LICENSE
                ));
            }
        } else if !external_license_allowed(license) {
            failures.push(format!(
                "{context}: external dependency {name} {version} license `{license}` has no approved compatible choice"
            ));
        }
    }
    Ok(failures)
}

fn gpl2_compatible_external_license(license: &str) -> bool {
    matches!(
        license,
        "MIT"
            | "MIT OR Apache-2.0"
            | "Apache-2.0 OR MIT"
            | "(MIT OR Apache-2.0) AND Unicode-3.0"
            | "BSD-2-Clause"
            | "BSD-3-Clause"
            | "ISC"
            | "Zlib"
            | "0BSD"
            | "CC0-1.0"
            | "GPL-2.0-only"
            | "GPL-2.0-or-later"
    )
}

fn permissive_external_license(license: &str) -> bool {
    matches!(
        license,
        "MIT"
            | "MIT OR Apache-2.0"
            | "Apache-2.0 OR MIT"
            | "(MIT OR Apache-2.0) AND Unicode-3.0"
            | "BSD-2-Clause"
            | "BSD-3-Clause"
            | "ISC"
            | "Zlib"
            | "0BSD"
            | "CC0-1.0"
    )
}

#[test]
fn resolved_graph_rejects_local_apache_and_external_gpl_boundary_regressions()
-> Result<(), Box<dyn Error>> {
    let metadata: JsonValue = serde_json::json!({
        "packages": [
            {"id": "plugin", "name": PLUGIN_PACKAGE, "version": "0.1.0", "license": PLUGIN_LICENSE, "source": null},
            {"id": "protocol", "name": "crucible-protocol", "version": "0.1.0", "license": super::BOUNDARY_LICENSE, "source": null},
            {"id": "aos-core", "name": "aos-core", "version": "0.1.0", "license": APACHE_LICENSE, "source": null},
            {"id": "apache", "name": "apache-fixture", "version": "1.0.0", "license": "Apache-2.0", "source": "registry+fixture"},
            {"id": "gpl", "name": "gpl-fixture", "version": "1.0.0", "license": "GPL-2.0-only", "source": "registry+fixture"}
        ],
        "resolve": {"nodes": [
            {"id": "plugin", "deps": [
                {"pkg": "protocol", "dep_kinds": [{"kind": null}]},
                {"pkg": "aos-core", "dep_kinds": [{"kind": null}]}
            ]},
            {"id": "protocol", "deps": [
                {"pkg": "apache", "dep_kinds": [{"kind": null}]},
                {"pkg": "gpl", "dep_kinds": [{"kind": "build"}]}
            ]},
            {"id": "aos-core", "deps": []},
            {"id": "apache", "deps": []},
            {"id": "gpl", "deps": []}
        ]}
    });
    let plugin_failures = resolved_production_graph_failures(
        &metadata,
        PLUGIN_PACKAGE,
        &[PLUGIN_PACKAGE, "crucible-protocol", "crucible-shmem"],
        gpl2_compatible_external_license,
        "plugin",
    )?;
    assert!(
        plugin_failures
            .iter()
            .any(|failure| failure.contains("aos-core"))
    );

    let boundary_failures = resolved_production_graph_failures(
        &metadata,
        "crucible-protocol",
        &["crucible-protocol", "crucible-shmem"],
        permissive_external_license,
        "crucible-protocol",
    )?;
    assert!(
        boundary_failures
            .iter()
            .any(|failure| failure.contains("gpl-fixture"))
    );
    assert!(
        boundary_failures
            .iter()
            .any(|failure| failure.contains("apache-fixture"))
    );
    Ok(())
}

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
        || package == "crucible-debug-gateway"
        || package.starts_with("crucible-qemu-plugin-")
        || package.ends_with("-qemu-plugin")
        || package.contains("-qemu-side-")
        || package.starts_with("qemu-crucible-internal-")
}
