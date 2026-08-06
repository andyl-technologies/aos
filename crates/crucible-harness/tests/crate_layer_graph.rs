//! Checks the Crucible runtime crate dependency graph.
//!
//! The L0-L4 crate map in RFC-0010 file 27 is a phase-ordering contract: a
//! runtime crate may depend only on crates in its own layer or lower layers,
//! except for the host-side QEMU adapter edge into the engine crate. The two
//! in-VM L2 crates may depend directly only on L1 crates.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
struct LayerSpec {
    package: &'static str,
    layer: u8,
    in_vm: bool,
}

const RUNTIME_SPECS: &[LayerSpec] = &[
    LayerSpec {
        package: "crucible-sim",
        layer: 0,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-assert",
        layer: 0,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-shmem",
        layer: 1,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-protocol",
        layer: 1,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-device",
        layer: 1,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-qemu",
        layer: 2,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-qemu-plugin",
        layer: 2,
        in_vm: true,
    },
    LayerSpec {
        package: "crucible-debug-gateway",
        layer: 2,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-guest",
        layer: 2,
        in_vm: true,
    },
    LayerSpec {
        package: "crucible",
        layer: 3,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-cas",
        layer: 3,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-session",
        layer: 4,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-api",
        layer: 4,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-daemon",
        layer: 4,
        in_vm: false,
    },
    LayerSpec {
        package: "crucible-cli",
        layer: 4,
        in_vm: false,
    },
];

const HARNESS_PACKAGE: &str = "crucible-harness";
const HOST_DRIVER_ENGINE_EDGE_EXCEPTIONS: &[(&str, &str)] = &[("crucible-qemu", "crucible")];

#[test]
fn crucible_runtime_dependencies_follow_layer_graph() -> Result<(), Box<dyn std::error::Error>> {
    let crates_dir = workspace_crates_dir()?;
    let layer_by_package = layer_by_package();
    let spec_by_package = spec_by_package();
    let mut graph = BTreeMap::new();
    let mut failures = Vec::new();

    assert_expected_runtime_package_set(&crates_dir, &mut failures)?;

    for spec in RUNTIME_SPECS {
        let manifest_path = crates_dir.join(spec.package).join("Cargo.toml");
        let content = fs::read_to_string(&manifest_path)?;
        let dependency_names = manifest_dependency_names(&content)?;
        let mut crucible_deps = BTreeSet::new();

        for dependency in dependency_names {
            if dependency == HARNESS_PACKAGE {
                failures.push(format!(
                    "{}: runtime crate must not depend on test-only `{HARNESS_PACKAGE}`",
                    display_repo_path(&manifest_path)
                ));
                continue;
            }

            let Some(dependency_layer) = layer_by_package.get(dependency.as_str()).copied() else {
                continue;
            };

            crucible_deps.insert(dependency.clone());
            if spec.in_vm && dependency_layer != 1 {
                failures.push(format!(
                    "{}: in-VM L2 crate `{}` may depend directly only on L1 crates, found `{}` in L{}",
                    display_repo_path(&manifest_path),
                    spec.package,
                    dependency,
                    dependency_layer
                ));
            } else if !spec.in_vm
                && dependency_layer > spec.layer
                && !allows_host_driver_engine_edge(spec.package, &dependency)
            {
                failures.push(format!(
                    "{}: upward dependency `{}` (L{}) -> `{}` (L{})",
                    display_repo_path(&manifest_path),
                    spec.package,
                    spec.layer,
                    dependency,
                    dependency_layer
                ));
            }
        }

        graph.insert(spec.package.to_string(), crucible_deps);
    }

    failures.extend(cycle_failures(&graph, &spec_by_package));

    assert!(
        failures.is_empty(),
        "Crucible crate layer graph lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn layer_graph_rules_reject_upward_edges_in_vm_l0_edges_and_cycles() {
    let mut graph = BTreeMap::new();
    graph.insert(
        "crucible-api".to_string(),
        BTreeSet::from([HARNESS_PACKAGE.to_string()]),
    );
    graph.insert(
        "crucible-sim".to_string(),
        BTreeSet::from(["crucible".to_string()]),
    );
    graph.insert(
        "crucible-qemu-plugin".to_string(),
        BTreeSet::from(["crucible-sim".to_string()]),
    );
    graph.insert(
        "crucible-protocol".to_string(),
        BTreeSet::from(["crucible-device".to_string()]),
    );
    graph.insert(
        "crucible-device".to_string(),
        BTreeSet::from(["crucible-protocol".to_string()]),
    );

    let failures = graph_rule_failures(&graph);

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("test-only `crucible-harness`")),
        "runtime dependency on harness should be rejected: {failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("upward dependency `crucible-sim`")),
        "upward dependency should be rejected: {failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("in-VM L2 crate `crucible-qemu-plugin`")),
        "direct in-VM dependency outside L1 should be rejected: {failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("dependency cycle")),
        "cycles should be rejected: {failures:?}"
    );

    let allowed_host_driver_graph = BTreeMap::from([
        (
            "crucible-qemu".to_string(),
            BTreeSet::from(["crucible".to_string()]),
        ),
        (
            "crucible".to_string(),
            BTreeSet::from(["crucible-sim".to_string()]),
        ),
    ]);
    let allowed_failures = graph_rule_failures(&allowed_host_driver_graph);
    assert!(
        allowed_failures.is_empty(),
        "host-side QEMU adapter edge into the engine should be allowed: {allowed_failures:?}"
    );
}

fn workspace_crates_dir() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("crucible-harness manifest is not inside crates/"))
}

fn assert_expected_runtime_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected: Vec<String> = RUNTIME_SPECS
        .iter()
        .map(|spec| spec.package.to_string())
        .collect();
    expected.push(HARNESS_PACKAGE.to_string());
    expected.sort();

    let mut found = Vec::new();
    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("crucible") {
            found.push(name);
        }
    }
    found.sort();

    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected [{}], found [{}]",
            expected.join(", "),
            found.join(", ")
        ));
    }

    Ok(())
}

fn manifest_dependency_names(
    manifest: &str,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let value: toml::Value = toml::from_str(manifest)?;
    let Some(dependencies) = value.get("dependencies").and_then(toml::Value::as_table) else {
        return Ok(BTreeSet::new());
    };

    Ok(dependencies
        .iter()
        .map(|(name, value)| dependency_package_name(name, value))
        .collect())
}

fn dependency_package_name(name: &str, value: &toml::Value) -> String {
    value
        .get("package")
        .and_then(toml::Value::as_str)
        .unwrap_or(name)
        .to_string()
}

fn graph_rule_failures(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let layer_by_package = layer_by_package();
    let spec_by_package = spec_by_package();
    let mut failures = Vec::new();

    for (package, dependencies) in graph {
        let Some(spec) = spec_by_package.get(package.as_str()) else {
            continue;
        };

        for dependency in dependencies {
            if dependency == HARNESS_PACKAGE {
                failures.push(format!(
                    "runtime crate `{}` must not depend on test-only `{HARNESS_PACKAGE}`",
                    spec.package
                ));
                continue;
            }

            let Some(dependency_layer) = layer_by_package.get(dependency.as_str()).copied() else {
                continue;
            };

            if spec.in_vm && dependency_layer != 1 {
                failures.push(format!(
                    "in-VM L2 crate `{}` may depend directly only on L1 crates, found `{}` in L{}",
                    spec.package, dependency, dependency_layer
                ));
            } else if !spec.in_vm
                && dependency_layer > spec.layer
                && !allows_host_driver_engine_edge(spec.package, dependency)
            {
                failures.push(format!(
                    "upward dependency `{}` (L{}) -> `{}` (L{})",
                    spec.package, spec.layer, dependency, dependency_layer
                ));
            }
        }
    }

    failures.extend(cycle_failures(graph, &spec_by_package));
    failures
}

fn allows_host_driver_engine_edge(package: &str, dependency: &str) -> bool {
    HOST_DRIVER_ENGINE_EDGE_EXCEPTIONS
        .iter()
        .any(|(allowed_package, allowed_dependency)| {
            package == *allowed_package && dependency == *allowed_dependency
        })
}

fn cycle_failures(
    graph: &BTreeMap<String, BTreeSet<String>>,
    spec_by_package: &BTreeMap<&'static str, LayerSpec>,
) -> Vec<String> {
    let mut failures = Vec::new();

    for package in spec_by_package.keys() {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack = Vec::new();

        if let Some(cycle) = find_cycle(package, graph, &mut visiting, &mut visited, &mut stack) {
            failures.push(format!("dependency cycle: {}", cycle.join(" -> ")));
        }
    }

    failures.sort();
    failures.dedup();
    failures
}

fn find_cycle(
    package: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    stack: &mut Vec<String>,
) -> Option<Vec<String>> {
    if visited.contains(package) {
        return None;
    }

    if visiting.contains(package) {
        let start = stack
            .iter()
            .position(|entry| entry == package)
            .unwrap_or_default();
        let mut cycle = stack[start..].to_vec();
        cycle.push(package.to_string());
        return Some(cycle);
    }

    visiting.insert(package.to_string());
    stack.push(package.to_string());

    if let Some(dependencies) = graph.get(package) {
        for dependency in dependencies {
            if let Some(cycle) = find_cycle(dependency, graph, visiting, visited, stack) {
                return Some(cycle);
            }
        }
    }

    stack.pop();
    visiting.remove(package);
    visited.insert(package.to_string());

    None
}

fn layer_by_package() -> BTreeMap<&'static str, u8> {
    RUNTIME_SPECS
        .iter()
        .map(|spec| (spec.package, spec.layer))
        .collect()
}

fn spec_by_package() -> BTreeMap<&'static str, LayerSpec> {
    RUNTIME_SPECS
        .iter()
        .map(|spec| (spec.package, *spec))
        .collect()
}

fn display_repo_path(path: &Path) -> String {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new(""));
    path.strip_prefix(crates_dir)
        .map(|relative| format!("crates/{}", relative.display()))
        .unwrap_or_else(|_| path.display().to_string())
}
