//! Checks the RFC-0010 per-layer gate-to-test-target map.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::campaign_gates::find_campaign_gate;
use crucible_harness::find_gate;
use crucible_harness::gate_targets::{GateTargetSpec, gate_targets};
use toml::Value;

struct ImplementedGateTestModel {
    package: &'static str,
    test_target: &'static str,
    gate_entry_point: &'static str,
    ignored_process_helpers: &'static [&'static str],
}

// Process helpers are test-harness entry points, but they must never replace
// the runnable test that exercises the gate under normal Cargo invocation.
const IMPLEMENTED_GATE_TEST_MODELS: &[ImplementedGateTestModel] = &[ImplementedGateTestModel {
    package: "crucible-daemon",
    test_target: "gate_campaign_component_contract",
    gate_entry_point: "same_campaign_survives_direct_rpc_and_independent_component_restarts",
    ignored_process_helpers: &["coordinator_process_helper", "executor_process_helper"],
}];

#[test]
fn per_layer_gates_have_named_isolable_test_targets() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut failures = Vec::new();

    for target in gate_targets() {
        let manifest_path = crates_dir.join(target.package).join("Cargo.toml");
        if !manifest_path.is_file() {
            failures.push(format!(
                "{}: package for {} does not exist",
                target.package, target.gate
            ));
            continue;
        }

        if find_gate(target.gate).is_none() && find_campaign_gate(target.gate).is_none() {
            failures.push(format!(
                "{}:{} references unknown canonical gate {}",
                target.package, target.test_target, target.gate
            ));
        }

        let test_path = crates_dir
            .join(target.package)
            .join("tests")
            .join(format!("{}.rs", target.test_target));
        if !test_path.is_file() {
            failures.push(format!(
                "{}: missing integration test target `{}` for {}",
                display_repo_path(&test_path, &root),
                target.test_target,
                target.gate
            ));
            continue;
        }

        let content = fs::read_to_string(&test_path)?;
        if target.placeholder {
            if !content.contains("#[ignore") || !content.contains("panic!") {
                failures.push(format!(
                    "{}: placeholder gate target must be ignored and fail when explicitly run",
                    display_repo_path(&test_path, &root)
                ));
            }
        } else {
            failures.extend(implemented_gate_test_failures(
                target,
                &content,
                &display_repo_path(&test_path, &root),
            ));
        }

        // Every feature-gated integration target must declare each feature in
        // its `[[test]]` entry and pin an explicit path so default workspace
        // test discovery cannot compile it under the wrong feature set.
        for required_feature in target.required_features {
            if !manifest_test_target_requires_feature(
                &fs::read_to_string(&manifest_path)?.parse()?,
                target.test_target,
                required_feature,
            ) {
                failures.push(format!(
                    "{}:{} Cargo manifest must set required-features containing {:?}",
                    target.package, target.test_target, required_feature
                ));
            }
        }

        if !target.required_features.is_empty()
            && !manifest_test_target_has_path(
                &fs::read_to_string(&manifest_path)?.parse()?,
                target.test_target,
                &format!("tests/{}.rs", target.test_target),
            )
        {
            failures.push(format!(
                "{}:{} Cargo manifest must set path = \"tests/{}.rs\"",
                target.package, target.test_target, target.test_target
            ));
        }

        // The `crucible` SimDouble gates specifically require test-double.
        let requires_test_double = crucible_gate_target_requires_test_double(target);
        if requires_test_double && target.required_features != ["test-double"].as_slice() {
            failures.push(format!(
                "{}:{} must run with --features test-double",
                target.package, target.test_target
            ));
        }
    }

    failures.extend(mapping_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible gate-target mapping lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn crate_structure_gate_targets_match_rfc_table() {
    let actual: BTreeSet<(&str, &str, &str)> = gate_targets()
        .iter()
        .map(|target| (target.gate, target.package, target.test_target))
        .collect();

    assert_eq!(
        actual,
        BTreeSet::from([
            ("gate:harness-lint", "crucible-harness", "harness_lint"),
            (
                "gate:license-boundary",
                "crucible-harness",
                "gate_license_boundary"
            ),
            (
                "gate:layer0-determinism",
                "crucible-sim",
                "gate_layer0_determinism"
            ),
            (
                "gate:layer0-determinism",
                "crucible-assert",
                "gate_layer0_determinism"
            ),
            (
                "gate:layer0-determinism",
                "crucible",
                "gate_layer0_determinism"
            ),
            (
                "gate:single-vm-fingerprint",
                "crucible",
                "gate_single_vm_fingerprint"
            ),
            (
                "gate:single-vm-fingerprint",
                "crucible-qemu",
                "gate_single_vm_fingerprint"
            ),
            (
                "gate:single-vm-fingerprint",
                "crucible-qemu-plugin",
                "gate_single_vm_fingerprint"
            ),
            (
                "gate:single-vm-fingerprint",
                "crucible-guest",
                "gate_single_vm_fingerprint"
            ),
            (
                "gate:layer1-injection",
                "crucible-device",
                "gate_layer1_injection"
            ),
            (
                "gate:layer1-injection",
                "crucible-protocol",
                "gate_layer1_injection"
            ),
            (
                "gate:layer1-injection",
                "crucible-shmem",
                "gate_layer1_injection"
            ),
            (
                "gate:abi-conformance",
                "crucible-harness",
                "gate_abi_conformance"
            ),
            (
                "gate:abi-conformance",
                "crucible-shmem",
                "gate_abi_conformance"
            ),
            (
                "gate:abi-conformance",
                "crucible-protocol",
                "gate_abi_conformance"
            ),
            (
                "gate:abi-conformance",
                "crucible-api",
                "gate_abi_conformance"
            ),
            (
                "gate:abi-conformance",
                "crucible-qemu-plugin",
                "gate_abi_conformance"
            ),
            (
                "gate:abi-conformance",
                "crucible-guest",
                "gate_abi_conformance"
            ),
            ("gate:abi-conformance", "crucible", "gate_abi_conformance"),
            ("gate:replay-oracle", "crucible", "gate_replay_oracle"),
            ("gate:content-address", "crucible", "gate_content_address"),
            (
                "gate:content-address",
                "crucible-sim",
                "gate_content_address"
            ),
            (
                "gate:campaign-model",
                "crucible-campaign",
                "gate_campaign_model"
            ),
            (
                "gate:campaign-statistics",
                "crucible-campaign",
                "gate_campaign_statistics"
            ),
            (
                "gate:branch-point-model",
                "crucible-campaign",
                "gate_branch_point_model"
            ),
            (
                "gate:lazy-frontier",
                "crucible-campaign",
                "gate_lazy_frontier"
            ),
            (
                "gate:attempt-idempotence",
                "crucible-campaign",
                "gate_attempt_idempotence"
            ),
            (
                "gate:campaign-mutation-scaling",
                "crucible-campaign",
                "gate_campaign_mutation_scaling"
            ),
            (
                "gate:campaign-store-equivalence",
                "crucible-cas",
                "gate_campaign_store_equivalence"
            ),
            (
                "gate:campaign-store-composition",
                "crucible-cas",
                "gate_campaign_store_composition"
            ),
            (
                "gate:campaign-store-composition",
                "crucible-cli",
                "gate_campaign_store_composition"
            ),
            (
                "gate:campaign-component-contract",
                "crucible-daemon",
                "gate_campaign_component_contract"
            ),
            (
                "gate:scheduler-liveness",
                "crucible",
                "gate_scheduler_liveness"
            ),
            (
                "gate:control-responsive",
                "crucible-session",
                "gate_control_responsive"
            ),
            (
                "gate:control-responsive",
                "crucible-api",
                "gate_control_responsive"
            ),
            (
                "gate:control-responsive",
                "crucible-daemon",
                "gate_control_responsive"
            ),
            ("gate:any-guest", "crucible-qemu", "gate_any_guest"),
            ("gate:qemu-inert", "crucible-qemu", "gate_qemu_inert"),
            ("gate:qemu-inert", "crucible-qemu-plugin", "gate_qemu_inert"),
            (
                "gate:patch-microtests",
                "crucible-qemu-plugin",
                "gate_patch_microtests"
            ),
            (
                "gate:divergence-bisect",
                "crucible-harness",
                "gate_divergence_bisect"
            ),
            (
                "gate:adversarial-determinism",
                "crucible",
                "gate_adversarial_determinism"
            ),
            (
                "gate:e2e-determinism",
                "crucible",
                "gate_e2e_determinism_concurrency"
            ),
            (
                "gate:e2e-determinism",
                "crucible-cli",
                "gate_e2e_determinism"
            ),
            (
                "gate:basic-block-coverage",
                "crucible",
                "gate_basic_block_coverage"
            ),
            (
                "gate:basic-block-coverage",
                "crucible-qemu",
                "gate_basic_block_coverage"
            ),
            (
                "gate:checkpoint-materialization",
                "crucible",
                "gate_checkpoint_materialization"
            ),
            (
                "gate:state-space-search",
                "crucible",
                "gate_state_space_search"
            ),
            (
                "gate:fleet-equivalence",
                "crucible",
                "gate_fleet_equivalence"
            ),
            (
                "gate:campaign-continuity",
                "crucible-cas",
                "gate_campaign_continuity"
            ),
            (
                "gate:typed-choice",
                "crucible-campaign",
                "gate_typed_choice"
            ),
            (
                "gate:signal-fault-system",
                "crucible",
                "gate_signal_fault_system"
            ),
            ("gate:perf-bench", "crucible-harness", "gate_perf_bench"),
        ])
    );
}

fn mapping_regression_failures() -> Vec<String> {
    let mut failures = Vec::new();
    let targets = [
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible",
            test_target: "gate_replay_oracle",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:harness-lint",
            package: "crucible-harness",
            test_target: "harness_lint",
            required_features: &[],
            placeholder: false,
        },
        GateTargetSpec {
            gate: "gate:unknown",
            package: "crucible-harness",
            test_target: "unknown_gate",
            required_features: &[],
            placeholder: true,
        },
    ];

    let ignored_implemented_target = BTreeMap::from([(
        ("crucible-harness", "harness_lint"),
        "#[test]\n#[ignore]\nfn harness_lint_gate() {}",
    )]);
    let feature_findings = synthetic_mapping_failures(&targets, &ignored_implemented_target);
    if !feature_findings
        .iter()
        .any(|finding| finding.contains("--features test-double"))
    {
        failures.push(
            "gate-target mapping regression failed to reject missing test-double feature"
                .to_string(),
        );
    }
    if !feature_findings
        .iter()
        .any(|finding| finding.contains("required-features"))
    {
        failures.push(
            "gate-target mapping regression failed to reject missing Cargo required-features"
                .to_string(),
        );
    }
    if !feature_findings
        .iter()
        .any(|finding| finding.contains("must set path"))
    {
        failures.push(
            "gate-target mapping regression failed to reject missing Cargo test path".to_string(),
        );
    }
    if !feature_findings
        .iter()
        .any(|finding| finding.contains("implemented gate target must not be ignored"))
    {
        failures.push(
            "gate-target mapping regression failed to reject ignored implemented target"
                .to_string(),
        );
    }
    if !feature_findings
        .iter()
        .any(|finding| finding.contains("unknown canonical gate"))
    {
        failures.push("gate-target mapping regression failed to reject unknown gate".to_string());
    }

    let component_target = GateTargetSpec {
        gate: "gate:campaign-component-contract",
        package: "crucible-daemon",
        test_target: "gate_campaign_component_contract",
        required_features: &[],
        placeholder: false,
    };
    let runnable_component_gate = r#"
        #[test]
        fn same_campaign_survives_direct_rpc_and_independent_component_restarts() {}

        #[test]
        #[ignore = "spawned process helper"]
        fn coordinator_process_helper() {}

        #[test]
        #[ignore = "spawned process helper"]
        fn executor_process_helper() {}
    "#;
    let runnable_findings = implemented_gate_test_failures(
        &component_target,
        runnable_component_gate,
        "synthetic component gate",
    );
    if !runnable_findings.is_empty() {
        failures.push(format!(
            "gate-target mapping regression rejected modeled process helpers: {}",
            runnable_findings.join(", ")
        ));
    }

    let ignored_entry_point = runnable_component_gate.replace(
        "#[test]\n        fn same_campaign_survives",
        "#[test]\n        #[ignore]\n        fn same_campaign_survives",
    );
    if !implemented_gate_test_failures(
        &component_target,
        &ignored_entry_point,
        "synthetic component gate",
    )
    .iter()
    .any(|finding| finding.contains("gate entry point") && finding.contains("must not be ignored"))
    {
        failures.push(
            "gate-target mapping regression failed to reject ignored component gate entry point"
                .to_string(),
        );
    }

    let unmodeled_helper = format!(
        "{runnable_component_gate}\n#[test]\n#[ignore]\nfn unmodeled_process_helper() {{}}"
    );
    if !implemented_gate_test_failures(
        &component_target,
        &unmodeled_helper,
        "synthetic component gate",
    )
    .iter()
    .any(|finding| finding.contains("unmodeled_process_helper"))
    {
        failures.push(
            "gate-target mapping regression failed to reject an unmodeled ignored helper"
                .to_string(),
        );
    }

    failures
}

fn synthetic_mapping_failures(
    targets: &[GateTargetSpec],
    file_contents: &BTreeMap<(&str, &str), &str>,
) -> Vec<String> {
    let mut failures = Vec::new();

    for target in targets {
        if find_gate(target.gate).is_none() && find_campaign_gate(target.gate).is_none() {
            failures.push(format!(
                "{}:{} references unknown canonical gate {}",
                target.package, target.test_target, target.gate
            ));
        }
        let requires_test_double = crucible_gate_target_requires_test_double(target);
        if requires_test_double && target.required_features != ["test-double"].as_slice() {
            failures.push(format!(
                "{}:{} must run with --features test-double",
                target.package, target.test_target
            ));
        }
        if requires_test_double {
            failures.push(format!(
                "{}:{} Cargo manifest must set required-features = [\"test-double\"]",
                target.package, target.test_target
            ));
            failures.push(format!(
                "{}:{} Cargo manifest must set path = \"tests/{}.rs\"",
                target.package, target.test_target, target.test_target
            ));
        }
        if let Some(content) = file_contents.get(&(target.package, target.test_target)) {
            if target.placeholder {
                if !content.contains("#[ignore") || !content.contains("panic!") {
                    failures.push(format!(
                        "{}:{} placeholder gate target must be ignored and fail when explicitly run",
                        target.package, target.test_target
                    ));
                }
            } else {
                failures.extend(implemented_gate_test_failures(
                    target,
                    content,
                    &format!("{}:{}", target.package, target.test_target),
                ));
            }
        } else if !target.placeholder {
            failures.push(format!(
                "{}:{} implemented gate target must not be ignored",
                target.package, target.test_target
            ));
        }
    }

    failures
}

fn implemented_gate_test_failures(
    target: &GateTargetSpec,
    content: &str,
    subject: &str,
) -> Vec<String> {
    let Some(model) = IMPLEMENTED_GATE_TEST_MODELS
        .iter()
        .find(|model| model.package == target.package && model.test_target == target.test_target)
    else {
        return content
            .contains("#[ignore")
            .then(|| format!("{subject}: implemented gate target must not be ignored"))
            .into_iter()
            .collect();
    };

    let tests = integration_test_functions(content);
    let mut failures = Vec::new();

    match tests.get(model.gate_entry_point) {
        Some(false) => {}
        Some(true) => failures.push(format!(
            "{subject}: implemented gate entry point `{}` must not be ignored",
            model.gate_entry_point
        )),
        None => failures.push(format!(
            "{subject}: must declare runnable gate entry point `{}`",
            model.gate_entry_point
        )),
    }

    for helper in model.ignored_process_helpers {
        match tests.get(*helper) {
            Some(true) => {}
            Some(false) => failures.push(format!(
                "{subject}: process helper `{helper}` must remain ignored"
            )),
            None => failures.push(format!(
                "{subject}: missing modeled process helper `{helper}`"
            )),
        }
    }

    for (name, ignored) in &tests {
        if *ignored && !model.ignored_process_helpers.contains(&name.as_str()) {
            failures.push(format!(
                "{subject}: ignored test `{name}` is not a modeled process helper"
            ));
        }
    }

    let ignored_attribute_count = content.match_indices("#[ignore").count();
    let ignored_test_count = tests.values().filter(|ignored| **ignored).count();
    if ignored_attribute_count != ignored_test_count {
        failures.push(format!(
            "{subject}: contains an ignored attribute outside a modeled test function"
        ));
    }

    failures
}

fn integration_test_functions(content: &str) -> BTreeMap<String, bool> {
    // Rustfmt emits test attributes and signatures one per line. Keeping this
    // parser narrow makes an unparsed `ignore` fail the raw-count check above.
    let mut tests = BTreeMap::new();
    let mut has_test_attribute = false;
    let mut has_ignore_attribute = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "#[test]" {
            has_test_attribute = true;
            has_ignore_attribute = false;
            continue;
        }
        if !has_test_attribute {
            continue;
        }
        if line.starts_with("#[ignore") {
            has_ignore_attribute = true;
            continue;
        }
        if line.starts_with("#[") || line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some(signature) = line
            .strip_prefix("fn ")
            .or_else(|| line.strip_prefix("async fn "))
            && let Some((name, _)) = signature.split_once('(')
        {
            tests.insert(name.trim().to_string(), has_ignore_attribute);
        }

        has_test_attribute = false;
        has_ignore_attribute = false;
    }

    tests
}

fn crucible_gate_target_requires_test_double(target: &GateTargetSpec) -> bool {
    target.package == "crucible"
        && matches!(
            target.gate,
            "gate:layer0-determinism"
                | "gate:single-vm-fingerprint"
                | "gate:abi-conformance"
                | "gate:replay-oracle"
                | "gate:content-address"
                | "gate:scheduler-liveness"
                | "gate:e2e-determinism"
                | "gate:fleet-equivalence"
        )
}

fn manifest_test_target_requires_feature(
    manifest: &Value,
    test_target: &str,
    feature: &str,
) -> bool {
    manifest
        .get("test")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_table)
        .any(|test| {
            test.get("name").and_then(Value::as_str) == Some(test_target)
                && test
                    .get("required-features")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|required| required == feature)
        })
}

fn manifest_test_target_has_path(manifest: &Value, test_target: &str, path: &str) -> bool {
    manifest
        .get("test")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_table)
        .any(|test| {
            test.get("name").and_then(Value::as_str) == Some(test_target)
                && test.get("path").and_then(Value::as_str) == Some(path)
        })
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn display_repo_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}
