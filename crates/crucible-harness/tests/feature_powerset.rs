//! Checks that Crucible feature flags are additive and resolvable.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::Value;

#[test]
fn crucible_features_resolve_for_declared_powersets() -> Result<(), Box<dyn Error>> {
    let workspace = workspace_manifest();
    for case in feature_cases() {
        let mut command = Command::new(env!("CARGO"));
        command
            .arg("check")
            .arg("--manifest-path")
            .arg(&workspace)
            .arg("--locked")
            .arg("--offline")
            .arg("-p")
            .arg(case.package);

        if case.no_default_features {
            command.arg("--no-default-features");
        }
        if !case.features.is_empty() {
            command.arg("--features").arg(case.features.join(","));
        }

        let output = command.output()?;
        assert!(
            output.status.success(),
            "feature case `{}` failed:\nstdout:\n{}\nstderr:\n{}",
            case.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[test]
fn crucible_manifest_feature_layout_is_explicit() -> Result<(), Box<dyn Error>> {
    let manifests = load_crucible_manifests()?;

    assert_features(
        &manifests,
        "crucible",
        &[
            ("default", &[][..]),
            ("test-support", &[][..]),
            ("test-double", &["dep:crucible-shmem"][..]),
        ],
    );
    assert_features(
        &manifests,
        "crucible-qemu",
        &[
            ("default", &[][..]),
            ("test-support", &["crucible/test-double"][..]),
        ],
    );
    assert_features(&manifests, "crucible-device", &[("default", &[][..])]);

    Ok(())
}

#[test]
fn crucible_guest_is_not_a_default_core_dependency() -> Result<(), Box<dyn Error>> {
    let manifests = load_crucible_manifests()?;
    let findings = default_guest_dependency_findings(&manifests, &core_packages());

    assert!(
        findings.is_empty(),
        "crucible-guest default dependency findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn shipped_crates_do_not_enable_the_test_double() -> Result<(), Box<dyn Error>> {
    let manifests = load_crucible_manifests()?;
    let findings = production_test_double_dependency_findings(&manifests, &shipped_packages());

    assert!(
        findings.is_empty(),
        "production test-double dependency findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn guest_dependency_policy_rejects_default_feature_activation() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        guest-double = { package = "crucible-guest", path = "../crucible-guest", optional = true }

        [features]
        default = ["with-guest"]
        with-guest = ["dep:guest-double"]
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible"), manifest)]);
    let findings = default_guest_dependency_findings(&manifests, &["crucible"]);

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("default feature activates")),
        "expected default-feature activation finding, got {findings:?}"
    );

    Ok(())
}

#[test]
fn guest_dependency_policy_rejects_direct_required_dependency() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        crucible-guest = { path = "../crucible-guest" }

        [features]
        default = []
    "#
    .parse()?;
    let manifests = BTreeMap::from([(String::from("crucible"), manifest)]);
    let findings = default_guest_dependency_findings(&manifests, &["crucible"]);

    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("required dependency")),
        "expected required-dependency finding, got {findings:?}"
    );

    Ok(())
}

fn core_packages() -> [&'static str; 10] {
    [
        "crucible-sim",
        "crucible-assert",
        "crucible-shmem",
        "crucible-protocol",
        "crucible-device",
        "crucible",
        "crucible-session",
        "crucible-api",
        "crucible-daemon",
        "crucible-cli",
    ]
}

fn shipped_packages() -> [&'static str; 12] {
    [
        "crucible-sim",
        "crucible-assert",
        "crucible-shmem",
        "crucible-protocol",
        "crucible-device",
        "crucible",
        "crucible-session",
        "crucible-api",
        "crucible-daemon",
        "crucible-cli",
        "crucible-qemu",
        "crucible-qemu-plugin",
    ]
}

#[derive(Clone, Debug)]
struct DependencySpec {
    key: String,
    package: String,
    optional: bool,
}

fn default_guest_dependency_findings(
    manifests: &BTreeMap<String, Value>,
    packages: &[&str],
) -> Vec<String> {
    let mut findings = Vec::new();

    for package in packages {
        let manifest = manifests
            .get(*package)
            .unwrap_or_else(|| panic!("missing manifest for `{package}`"));
        let empty_dependencies = toml::map::Map::new();
        let empty_features = toml::map::Map::new();
        let dependencies = manifest
            .get("dependencies")
            .and_then(Value::as_table)
            .unwrap_or(&empty_dependencies);
        let features = manifest
            .get("features")
            .and_then(Value::as_table)
            .unwrap_or(&empty_features);
        let default_closure = default_feature_closure(features);

        for dependency in dependency_specs(dependencies) {
            if dependency.package != "crucible-guest" {
                continue;
            }

            if !dependency.optional {
                findings.push(format!(
                    "`{package}` has required dependency `{}` on crucible-guest",
                    dependency.key
                ));
                continue;
            }

            if default_closure
                .iter()
                .any(|feature| activates_dependency(feature, &dependency))
            {
                findings.push(format!(
                    "`{package}` default feature activates optional crucible-guest dependency `{}`",
                    dependency.key
                ));
            }
        }
    }

    findings
}

fn production_test_double_dependency_findings(
    manifests: &BTreeMap<String, Value>,
    packages: &[&str],
) -> Vec<String> {
    let mut findings = Vec::new();

    for package in packages {
        let manifest = manifests
            .get(*package)
            .unwrap_or_else(|| panic!("missing manifest for `{package}`"));
        let empty_dependencies = toml::map::Map::new();
        let dependencies = manifest
            .get("dependencies")
            .and_then(Value::as_table)
            .unwrap_or(&empty_dependencies);
        let Some(crucible_dependency) = dependencies.get("crucible").and_then(Value::as_table)
        else {
            continue;
        };
        let enables_test_double = crucible_dependency
            .get("features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|feature| feature == "test-double");
        if enables_test_double {
            findings.push(format!(
                "`{package}` enables crucible/test-double in production dependencies"
            ));
        }
    }

    findings
}

fn dependency_specs(dependencies: &toml::map::Map<String, Value>) -> Vec<DependencySpec> {
    dependencies
        .iter()
        .map(|(key, value)| {
            let package = value
                .as_table()
                .and_then(|table| table.get("package"))
                .and_then(Value::as_str)
                .unwrap_or(key)
                .to_owned();
            let optional = value
                .as_table()
                .and_then(|table| table.get("optional"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            DependencySpec {
                key: key.to_owned(),
                package,
                optional,
            }
        })
        .collect()
}

fn default_feature_closure(features: &toml::map::Map<String, Value>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = feature_members(features, "default");

    while let Some(feature) = stack.pop() {
        if !seen.insert(feature.clone()) {
            continue;
        }

        stack.extend(feature_members(features, &feature));
    }

    seen
}

fn feature_members(features: &toml::map::Map<String, Value>, name: &str) -> Vec<String> {
    features
        .get(name)
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn activates_dependency(feature: &str, dependency: &DependencySpec) -> bool {
    dependency_aliases(dependency).iter().any(|alias| {
        feature == *alias
            || feature == format!("dep:{alias}")
            || feature.starts_with(&format!("{alias}/"))
            || feature.starts_with(&format!("{alias}?/"))
    })
}

fn dependency_aliases(dependency: &DependencySpec) -> BTreeSet<&str> {
    BTreeSet::from([dependency.key.as_str(), dependency.package.as_str()])
}

#[derive(Clone, Debug)]
struct FeatureCase {
    name: &'static str,
    package: &'static str,
    no_default_features: bool,
    features: &'static [&'static str],
}

fn feature_cases() -> &'static [FeatureCase] {
    &[
        FeatureCase {
            name: "crucible default",
            package: "crucible",
            no_default_features: false,
            features: &[],
        },
        FeatureCase {
            name: "crucible no default",
            package: "crucible",
            no_default_features: true,
            features: &[],
        },
        FeatureCase {
            name: "crucible test-support",
            package: "crucible",
            no_default_features: true,
            features: &["test-support"],
        },
        FeatureCase {
            name: "crucible test-double",
            package: "crucible",
            no_default_features: true,
            features: &["test-double"],
        },
        FeatureCase {
            name: "crucible all features",
            package: "crucible",
            no_default_features: true,
            features: &["test-support", "test-double"],
        },
        FeatureCase {
            name: "crucible-qemu production",
            package: "crucible-qemu",
            no_default_features: true,
            features: &[],
        },
        FeatureCase {
            name: "crucible-qemu test support",
            package: "crucible-qemu",
            no_default_features: true,
            features: &["test-support"],
        },
        FeatureCase {
            name: "crucible-device default",
            package: "crucible-device",
            no_default_features: false,
            features: &[],
        },
        FeatureCase {
            name: "crucible-device no default",
            package: "crucible-device",
            no_default_features: true,
            features: &[],
        },
    ]
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn workspace_manifest() -> PathBuf {
    workspace_root().join("crates/Cargo.toml")
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

fn assert_features(
    manifests: &BTreeMap<String, Value>,
    package: &str,
    expected: &[(&str, &[&str])],
) {
    let features = manifest_table(manifests, package, "features");
    let expected_names: BTreeSet<&str> = expected.iter().map(|(name, _)| *name).collect();
    let actual_names: BTreeSet<&str> = features.keys().map(String::as_str).collect();
    assert_eq!(
        actual_names, expected_names,
        "`{package}` feature names drifted"
    );

    for (name, expected_values) in expected {
        let actual_values: Vec<&str> = features
            .get(*name)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("`{package}` feature `{name}` is not an array"))
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("`{package}` feature `{name}` contains non-string"))
            })
            .collect();
        assert_eq!(
            actual_values, *expected_values,
            "`{package}` feature `{name}` values drifted"
        );
    }
}

fn manifest_table<'a>(
    manifests: &'a BTreeMap<String, Value>,
    package: &str,
    table: &str,
) -> &'a toml::map::Map<String, Value> {
    manifests
        .get(package)
        .unwrap_or_else(|| panic!("missing manifest for `{package}`"))
        .get(table)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("`{package}` lacks [{table}]"))
}
