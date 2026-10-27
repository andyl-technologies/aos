//! Applies the existing license gate to declared Bazel compilation metadata.
//!
//! Production edges union every declared platform and feature branch. External
//! package membership comes from separate configured single-root analyses,
//! including procedural macros and build-script compilation dependencies.
//!
//! Closure package records use tagged source ownership; SDK records also carry
//! the pinned archive digest (abbreviated here):
//!
//! ```json
//! [
//!   {
//!     "name": "crucible-qemu-protocol", "version": "0.1.0",
//!     "license": "MIT OR Apache-2.0", "source": "local",
//!     "directory": "crates/crucible/crucible-qemu-protocol",
//!     "compilation_targets": ["//crates/crucible/crucible-qemu-protocol:lib"]
//!   },
//!   {
//!     "name": "example", "version": "1.0.0", "license": "MIT",
//!     "source": "sdk", "repository": "aos_sdk__example-1.0.0",
//!     "sha256": "...",
//!     "compilation_targets": ["@@+aos_tools_repository+aos_sdk__example-1.0.0//:example"]
//!   }
//! ]
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io;

use sha2::{Digest, Sha256};

use super::architecture::{self, Architecture};

const SELECTION: &str =
    "configured Rust compilation closures, including build scripts and procedural macros";

/// Checks explicit source-package licenses against the existing component policy.
///
/// # Errors
///
/// Returns an error for absent source licenses or inconsistent ownership.
pub(super) fn component_licenses(graph: &Architecture) -> Result<(), Box<dyn Error>> {
    for name in graph.package_names() {
        assert_eq!(
            graph.package_license(name)?,
            super::expected_license(name),
            "declared Bazel component license drift: {name}"
        );
    }
    Ok(())
}

/// Checks all declared GPL-side production branches and boundary licenses.
///
/// # Errors
///
/// Returns an error for missing production edges or source identities.
pub(super) fn internal_boundaries(graph: &Architecture) -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();
    for name in [super::PLUGIN_PACKAGE, super::DEBUG_GATEWAY_PACKAGE] {
        for dependency in graph.production_dependencies(name)? {
            if dependency.starts_with("crucible-")
                && !super::BOUNDARY_PACKAGES.contains(&dependency.as_str())
            {
                failures.push(format!(
                    "{name}: production Bazel entry `{dependency}` crosses the GPL boundary"
                ));
            }
        }
    }
    for name in super::BOUNDARY_PACKAGES {
        assert_eq!(
            graph.package_license(name)?,
            super::BOUNDARY_LICENSE,
            "{name} must remain GPL-compatible"
        );
    }
    Ok(failures)
}

/// Checks every non-GPL production package against QEMU implementation edges.
///
/// # Errors
///
/// Returns an error for absent production graphs or license identities.
pub(super) fn non_gpl_boundaries(graph: &Architecture) -> Result<(), Box<dyn Error>> {
    let mut failures = Vec::new();
    for name in graph.package_names() {
        if graph.package_license(name)? == super::PLUGIN_LICENSE {
            continue;
        }
        if name == "crucible-test-support" {
            let targets: Vec<_> = graph.compilation_targets(name)?.collect();
            if targets.is_empty() || targets.iter().any(|(_, target)| !target.test_only) {
                return Err(
                    "test support lacks an exclusively test-only Bazel compilation surface".into(),
                );
            }
            continue;
        }
        for dependency in graph.production_dependencies(name)? {
            let local_gpl = graph.package_names().any(|name| name == dependency)
                && graph.package_license(dependency)? == super::PLUGIN_LICENSE;
            if local_gpl || super::dependencies::is_qemu_side_implementation_name(dependency) {
                failures.push(format!("{name}: production Bazel entry resolves to forbidden QEMU-side package `{dependency}`"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "non-GPL crate dependency boundary drift:\n{}",
        failures.join("\n")
    );
    Ok(())
}

/// Checks the declared library artifact roles without reading Cargo manifests.
///
/// # Errors
///
/// Returns an error when the library source root or compilation role is absent.
pub(super) fn artifact_types(graph: &Architecture) -> Result<(), Box<dyn Error>> {
    for name in [super::PLUGIN_PACKAGE]
        .into_iter()
        .chain(super::BOUNDARY_PACKAGES.iter().copied())
    {
        let expected = if name == super::PLUGIN_PACKAGE {
            "rust_shared_library"
        } else {
            "rust_library"
        };
        let libraries: Vec<_> = graph
            .compilation_targets(name)?
            .filter(|(_, target)| !target.test_only && target.crate_roots.contains("src/lib.rs"))
            .collect();
        if libraries.is_empty() || libraries.iter().any(|(_, target)| target.kind != expected) {
            return Err(
                format!("{name}: declared Bazel library artifact must be {expected}").into(),
            );
        }
    }
    Ok(())
}

/// Holds the configured production roots bound to the declared source graph.
pub(super) struct Closures {
    roots: BTreeMap<String, Closure>,
}

#[derive(serde::Deserialize)]
struct Document {
    schema_version: u32,
    selection: String,
    architecture_sha256: String,
    sdk_manifest_sha256: BTreeMap<String, String>,
    closures: BTreeMap<String, Closure>,
}

#[derive(serde::Deserialize)]
struct Closure {
    root: String,
    root_package: String,
    inventory_sha256: String,
    packages: Vec<Package>,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
    version: String,
    license: String,
    compilation_targets: BTreeSet<String>,
    #[serde(flatten)]
    source: Source,
}

#[derive(serde::Deserialize)]
#[serde(tag = "source")]
enum Source {
    #[serde(rename = "local")]
    Local { directory: String },
    #[serde(rename = "sdk")]
    Sdk { repository: String, sha256: String },
}

/// Loads configured package closures only when the Bazel backend is selected.
///
/// # Errors
///
/// Returns an error for missing inputs, stale source bindings, or invalid owners.
pub(super) fn load() -> Result<Option<Closures>, Box<dyn Error>> {
    let Some(graph) = architecture::load()? else {
        if std::env::var_os("AOS_BAZEL_LICENSE_CLOSURES").is_some() {
            return Err("license closures require their declared architecture input".into());
        }
        return Ok(None);
    };
    let path = std::env::var_os("AOS_BAZEL_LICENSE_CLOSURES")
        .ok_or("Bazel license audit omitted its configured closure input")?;
    let graph_path = std::env::var_os("AOS_BAZEL_ARCHITECTURE")
        .ok_or("Bazel license audit omitted its architecture input")?;
    let graph_bytes = fs::read(graph_path)?;
    let document: Document = serde_json::from_slice(&fs::read(path)?)?;
    validate(
        document,
        &graph,
        &format!("{:x}", Sha256::digest(graph_bytes)),
    )
    .map(Some)
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate(
    document: Document,
    graph: &Architecture,
    graph_digest: &str,
) -> Result<Closures, Box<dyn Error>> {
    if document.schema_version != 1
        || document.selection != SELECTION
        || document.architecture_sha256 != graph_digest
        || document.sdk_manifest_sha256.is_empty()
        || !document
            .sdk_manifest_sha256
            .values()
            .all(|hash| digest(hash))
        || document.closures.is_empty()
    {
        return Err("invalid or stale configured license closure identity".into());
    }

    let mut roots = BTreeMap::new();
    for (label, closure) in document.closures {
        let declared = graph
            .compilation_targets(&closure.root_package)?
            .find(|(target, _)| *target == label);
        if label != closure.root
            || !digest(&closure.inventory_sha256)
            || declared.is_none_or(|(_, target)| target.test_only)
            || closure.packages.is_empty()
        {
            return Err("license closure has no declared production root".into());
        }

        let mut owners = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut root_seen = false;
        for package in &closure.packages {
            if package.name.is_empty()
                || package.version.is_empty()
                || package.license.is_empty()
                || package.compilation_targets.is_empty()
            {
                return Err("configured license package omitted its identity".into());
            }
            let owner = match &package.source {
                Source::Local { directory } => {
                    if graph.package_directory(&package.name)?.to_str() != Some(directory.as_str())
                        || graph.package_license(&package.name)? != package.license
                        || graph.package_version(&package.name)? != package.version
                    {
                        return Err(
                            "configured local license identity differs from source ownership"
                                .into(),
                        );
                    }
                    let declared: BTreeSet<_> = graph
                        .compilation_targets(&package.name)?
                        .filter(|(_, target)| !target.test_only)
                        .map(|(label, _)| label)
                        .collect();
                    if package
                        .compilation_targets
                        .iter()
                        .any(|label| !declared.contains(label.as_str()))
                    {
                        return Err(
                            "configured local license target has no production declaration".into(),
                        );
                    }
                    root_seen |= package.name == closure.root_package
                        && package.compilation_targets.contains(&closure.root);
                    format!("local:{directory}")
                }
                Source::Sdk { repository, sha256 } => {
                    let prefix = format!("@@+aos_tools_repository+{repository}//:");
                    if repository.is_empty()
                        || !digest(sha256)
                        || package
                            .compilation_targets
                            .iter()
                            .any(|label| !label.starts_with(&prefix))
                    {
                        return Err(
                            "configured SDK license target has no pinned source identity".into(),
                        );
                    }
                    format!("sdk:{repository}")
                }
            };
            if !owners.insert(owner)
                || package
                    .compilation_targets
                    .iter()
                    .any(|label| !targets.insert(label))
            {
                return Err("duplicate configured license package or compilation ownership".into());
            }
        }
        if !root_seen
            || roots
                .insert(closure.root_package.clone(), closure)
                .is_some()
        {
            return Err("configured license closure omitted or duplicated its root package".into());
        }
    }
    Ok(Closures { roots })
}

impl Closures {
    /// Applies the original local-package and external-license policy to a root.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested production root was not analyzed.
    pub(super) fn failures(
        &self,
        root: &str,
        allowed_local: &[&str],
        license_allowed: fn(&str) -> bool,
        context: &str,
    ) -> io::Result<Vec<String>> {
        let closure = self.roots.get(root).ok_or_else(|| {
            io::Error::other("configured license closure omitted the requested root")
        })?;
        let mut failures = Vec::new();
        for package in &closure.packages {
            let name = package.name.as_str();
            let license = package.license.as_str();
            match package.source {
                Source::Local { .. } if !allowed_local.contains(&name) => failures.push(format!(
                    "{context}: reachable local package `{name}` is not an approved boundary dependency"
                )),
                Source::Local { .. } if name != root && license != super::BOUNDARY_LICENSE => failures.push(format!(
                    "{context}: local boundary package `{name}` must declare `{}`, found `{license}`",
                    super::BOUNDARY_LICENSE
                )),
                Source::Sdk { .. } if !license_allowed(license) => failures.push(format!(
                    "{context}: external dependency {name} {} license `{license}` has no approved compatible choice",
                    package.version
                )),
                _ => {}
            }
        }
        Ok(failures)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::dependencies::{gpl2_compatible_external_license, permissive_external_license};

    fn fixture() -> (Value, Value) {
        let mut graph = json!({
            "schema_version": 1,
            "selection": "union of all declared production platform/feature branches",
            "query_sha256": "a".repeat(64),
            "packages": [], "target_dependencies": {}, "compilation_targets": {},
        });
        for (name, kind, license) in [
            (
                "crucible-qemu-plugin",
                "rust_shared_library",
                "GPL-2.0-only",
            ),
            (
                "crucible-qemu-protocol",
                "rust_library",
                "MIT OR Apache-2.0",
            ),
        ] {
            let directory = format!("crates/crucible/{name}");
            let target = format!("//{directory}:lib");
            graph["packages"].as_array_mut().unwrap().push(json!({
                "name": name, "directory": directory, "version": "0.1.0", "license": license,
                "production_targets": [target], "production_dependencies": [],
            }));
            graph["target_dependencies"][&target] = json!([]);
            graph["compilation_targets"][&target] = json!({
                "package": name, "kind": kind, "crate_name": name.replace('-', "_"),
                "crate_roots": ["src/lib.rs"], "features": [], "tags": [], "test_only": false,
            });
        }
        let target = "//crates/crucible/crucible-qemu-plugin:lib";
        let document = json!({
            "schema_version": 1, "selection": SELECTION,
            "architecture_sha256": "b".repeat(64),
            "sdk_manifest_sha256": {"fixture/sources.json": "c".repeat(64)},
            "closures": {target: {
                "root": target, "root_package": "crucible-qemu-plugin", "inventory_sha256": "d".repeat(64),
                "packages": [
                    {"source": "local", "name": "crucible-qemu-plugin", "version": "0.1.0", "license": "GPL-2.0-only",
                     "directory": "crates/crucible/crucible-qemu-plugin", "compilation_targets": [target]},
                    {"source": "local", "name": "crucible-qemu-protocol", "version": "0.1.0", "license": "MIT OR Apache-2.0",
                     "directory": "crates/crucible/crucible-qemu-protocol", "compilation_targets": ["//crates/crucible/crucible-qemu-protocol:lib"]},
                    {"source": "sdk", "name": "external-fixture", "version": "1.0.0", "license": "MIT", "repository": "fixture",
                     "sha256": "e".repeat(64), "compilation_targets": ["@@+aos_tools_repository+fixture//:lib"]},
                ],
            }},
        });
        (graph, document)
    }

    fn parse_fixture(graph: &Value, document: Value) -> Result<Closures, Box<dyn Error>> {
        let graph = architecture::parse(&graph.to_string())?;
        validate(serde_json::from_value(document)?, &graph, &"b".repeat(64))
    }

    #[test]
    fn configured_closures_apply_the_existing_external_license_choices() {
        let (graph, mut document) = fixture();
        let target = "//crates/crucible/crucible-qemu-plugin:lib";
        let allowed = ["crucible-qemu-plugin", "crucible-qemu-protocol"];

        let valid = parse_fixture(&graph, document.clone()).unwrap();
        assert!(
            valid
                .failures(
                    "crucible-qemu-plugin",
                    &allowed,
                    gpl2_compatible_external_license,
                    "plugin"
                )
                .unwrap()
                .is_empty()
        );

        document["closures"][target]["packages"][2]["license"] = json!("Apache-2.0");
        let invalid = parse_fixture(&graph, document.clone()).unwrap();
        assert_eq!(
            invalid
                .failures(
                    "crucible-qemu-plugin",
                    &allowed,
                    gpl2_compatible_external_license,
                    "plugin"
                )
                .unwrap()
                .len(),
            1
        );

        document["closures"][target]["packages"][2]["license"] = json!("GPL-2.0-only");
        let gpl = parse_fixture(&graph, document).unwrap();
        assert!(
            gpl.failures(
                "crucible-qemu-plugin",
                &allowed,
                gpl2_compatible_external_license,
                "plugin"
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            gpl.failures(
                "crucible-qemu-plugin",
                &allowed,
                permissive_external_license,
                "boundary"
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn configured_closures_reject_unapproved_local_boundary_packages() {
        let (graph, document) = fixture();
        let closures = parse_fixture(&graph, document).unwrap();

        let failures = closures
            .failures(
                "crucible-qemu-plugin",
                &["crucible-qemu-plugin"],
                gpl2_compatible_external_license,
                "plugin",
            )
            .unwrap();

        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("not an approved boundary dependency"))
        );
        assert!(
            closures
                .failures("absent-root", &[], permissive_external_license, "boundary")
                .is_err()
        );
    }

    #[test]
    fn configured_closures_reject_stale_or_incomplete_source_identities() {
        let (graph, original) = fixture();
        let target = "//crates/crucible/crucible-qemu-plugin:lib";
        let mut variants = Vec::new();
        let mut document = original.clone();
        document["architecture_sha256"] = json!("0".repeat(64));
        variants.push(document);
        for (field, value) in [
            ("license", json!("")),
            ("version", json!("9.0.0")),
            ("directory", json!("crates/other")),
            ("compilation_targets", json!([])),
        ] {
            let mut document = original.clone();
            document["closures"][target]["packages"][0][field] = value;
            variants.push(document);
        }
        for (field, value) in [
            ("sha256", json!("missing")),
            ("repository", json!("unowned")),
        ] {
            let mut document = original.clone();
            document["closures"][target]["packages"][2][field] = value;
            variants.push(document);
        }
        let mut document = original.clone();
        document["closures"][target]["packages"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        variants.push(document);
        let mut document = original.clone();
        let duplicate = document["closures"][target]["packages"][2].clone();
        document["closures"][target]["packages"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        variants.push(document);

        for document in variants {
            assert!(parse_fixture(&graph, document).is_err());
        }
    }
}
