//! Checks that `crucible-harness` hosts the cross-crate gate building blocks.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::abi::{GoldenVectorCase, GoldenVectorMismatchKind, run_golden_vectors};
use crucible_harness::adversarial::{
    AdversarialComparisonError, AdversarialMismatchKind, AdversarialRun, HostileProfile,
    compare_adversarial_runs,
};
use crucible_harness::divergence::{bisect_first_different_icount, locate_first_divergence};
use crucible_harness::fingerprint::{
    FingerprintMismatchKind, FingerprintSample, FingerprintSampleTrigger, FingerprintStream,
    compare_fingerprint_streams,
};
use crucible_harness::replay_oracle::{ReplayOracleCase, check_replay_oracle};
use crucible_harness::{find_gate, harness_components};
use toml::Value;

#[test]
fn harness_component_catalog_hosts_required_gate_building_blocks() {
    let components: BTreeSet<(&str, &str, &str)> = harness_components()
        .iter()
        .map(|component| (component.name, component.module, component.gate))
        .collect();

    assert_eq!(
        components,
        BTreeSet::from([
            (
                "fingerprint comparator",
                "fingerprint",
                "gate:single-vm-fingerprint"
            ),
            (
                "divergence bisector",
                "divergence",
                "gate:divergence-bisect"
            ),
            (
                "replay-oracle checker",
                "replay_oracle",
                "gate:replay-oracle"
            ),
            ("ABI golden-vector runner", "abi", "gate:abi-conformance"),
            (
                "adversarial driver",
                "adversarial",
                "gate:adversarial-determinism"
            ),
        ])
    );

    for component in harness_components() {
        assert!(
            find_gate(component.gate).is_some(),
            "{} references unknown gate {}",
            component.name,
            component.gate
        );
    }
}

#[test]
fn component_building_blocks_report_first_mismatch() -> Result<(), Box<dyn Error>> {
    let left_stream = FingerprintStream {
        definition_digest: vec![8],
        samples: vec![sample(0, "node-a", 10, &[1]), sample(1, "node-a", 20, &[2])],
        final_fingerprint: vec![9],
    };
    let right_stream = FingerprintStream {
        definition_digest: vec![8],
        samples: vec![sample(0, "node-a", 10, &[1]), sample(1, "node-a", 20, &[3])],
        final_fingerprint: vec![9],
    };

    let mismatch = must_err(
        compare_fingerprint_streams(&left_stream, &right_stream),
        "sample mismatch should be reported",
    );
    assert!(matches!(
        &mismatch.kind,
        FingerprintMismatchKind::Sample { .. }
    ));
    assert_eq!(mismatch.sample_index, 1);

    let report = must_some(
        locate_first_divergence(&left_stream, &right_stream),
        "divergence should be localized",
    );
    assert_eq!(report.sample_index, 1);
    assert_eq!(report.node.as_deref(), Some("node-a"));
    assert_eq!(report.previous_matching_icount, Some(10));
    assert_eq!(report.first_different_sample_icount, Some(20));

    let first_diff = bisect_first_different_icount(0, 8, |icount| icount < 5)?;
    assert_eq!(first_diff, 5);

    let replay_mismatch = must_err(
        check_replay_oracle(&[ReplayOracleCase {
            checkpoint_id: "cp-1".to_string(),
            fat_hash: vec![1],
            thin_hash: vec![2],
        }]),
        "hash mismatch should fail replay oracle",
    );
    assert_eq!(replay_mismatch.checkpoint_id, "cp-1");

    let vector_mismatch = must_err(
        run_golden_vectors(&[GoldenVectorCase {
            name: "frame-v1".to_string(),
            expected_version: 1,
            actual_version: 2,
            expected_bytes: vec![1, 2, 3],
            actual_bytes: vec![1, 2, 3],
        }]),
        "version mismatch should fail ABI conformance",
    );
    assert!(matches!(
        vector_mismatch.kind,
        GoldenVectorMismatchKind::Version {
            expected: 1,
            actual: 2
        }
    ));

    let adversarial_mismatch = must_err(
        compare_adversarial_runs(&[
            adversarial_run("one-core", &[1], &[9]),
            adversarial_run("many-core", &[2], &[9]),
        ]),
        "canonical log mismatch should fail adversarial comparison",
    );
    assert!(matches!(
        adversarial_mismatch,
        AdversarialComparisonError::Mismatch(mismatch)
            if mismatch.kind == AdversarialMismatchKind::CanonicalLog
    ));

    Ok(())
}

fn must_err<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn must_some<T>(option: Option<T>, message: &str) -> T {
    match option {
        Some(value) => value,
        None => panic!("{message}"),
    }
}

#[test]
fn crucible_harness_is_dev_dependency_only() -> Result<(), Box<dyn Error>> {
    let crates_dir = workspace_root().join("crates");
    let workspace_manifest: Value = fs::read_to_string(crates_dir.join("Cargo.toml"))?.parse()?;
    let workspace_dependencies = workspace_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let harness_manifest: Value =
        fs::read_to_string(crates_dir.join("crucible-harness/Cargo.toml"))?.parse()?;
    let normal_dependencies = harness_manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .map(|dependencies| dependencies.len())
        .unwrap_or_default();
    assert_eq!(
        normal_dependencies, 0,
        "crucible-harness must keep third-party crates as dev-dependencies only"
    );

    let mut failures = Vec::new();
    for entry in fs::read_dir(&crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let package_dir_name = entry.file_name().to_string_lossy().into_owned();
        if package_dir_name == "crucible-harness" {
            continue;
        }

        let manifest_path = path.join("Cargo.toml");
        let manifest: Value = fs::read_to_string(&manifest_path)?.parse()?;
        for dependency in production_dependency_specs(&manifest, &workspace_dependencies) {
            if dependency.package == "crucible-harness" {
                failures.push(format!(
                    "{} has production dependency `{}` on crucible-harness in {}",
                    package_dir_name, dependency.key, dependency.scope
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "crucible-harness must not enter release/runtime dependency graphs:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn dev_dependency_lint_rejects_workspace_inherited_harness_dependency() -> Result<(), Box<dyn Error>>
{
    let manifest: Value = r#"
        [package]
        name = "crucible-daemon"
        version = "0.1.0"
        edition = "2024"

        [target.'cfg(unix)'.dependencies]
        harness = { workspace = true }
    "#
    .parse()?;
    let workspace_manifest: Value = r#"
        [workspace.dependencies]
        harness = { package = "crucible-harness", path = "crucible-harness" }
    "#
    .parse()?;
    let workspace_dependencies = workspace_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();
    let dependency_specs = production_dependency_specs(&manifest, &workspace_dependencies);

    assert!(
        dependency_specs
            .iter()
            .any(|dependency| dependency.package == "crucible-harness"),
        "workspace-inherited harness production dependency should be detected: {dependency_specs:?}"
    );

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DependencySpec {
    key: String,
    package: String,
    scope: String,
}

fn production_dependency_specs(
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
        "build-dependencies",
        workspace_dependencies,
    ));

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, value) in targets {
            specs.extend(dependency_table_specs(
                value,
                &format!("target.{target}.dependencies"),
                workspace_dependencies,
            ));
            specs.extend(dependency_table_specs(
                value,
                &format!("target.{target}.build-dependencies"),
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
        .get(scope.rsplit('.').next().unwrap_or(scope))
        .and_then(Value::as_table)
        .map(|dependencies| {
            dependencies
                .iter()
                .map(|(key, value)| DependencySpec {
                    key: key.to_owned(),
                    package: dependency_package_name(key, value, workspace_dependencies),
                    scope: scope.to_owned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dependency_package_name(
    key: &str,
    value: &Value,
    workspace_dependencies: &toml::map::Map<String, Value>,
) -> String {
    if value
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
    }
}

fn sample(seq: u64, node: &str, icount: u64, rolling_fingerprint: &[u8]) -> FingerprintSample {
    FingerprintSample {
        seq,
        node: node.to_string(),
        icount,
        trigger: FingerprintSampleTrigger::Periodic,
        rolling_fingerprint: rolling_fingerprint.to_vec(),
    }
}

fn adversarial_run(
    profile: &str,
    canonical_log: &[u8],
    final_fingerprint: &[u8],
) -> AdversarialRun {
    AdversarialRun {
        profile: HostileProfile {
            name: profile.to_string(),
        },
        canonical_log: canonical_log.to_vec(),
        final_fingerprint: final_fingerprint.to_vec(),
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}
