//! Checks the RFC-0010 per-layer testing standards.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::gate_targets::{GateTargetSpec, gate_targets};

type GateSourceOverrides = BTreeMap<(&'static str, &'static str), String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    L0,
    L1,
    L2,
    L3,
    L4,
    CrossCutting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestBackend {
    InProcess,
    SimDouble,
    RealQemu,
    Mixed,
    StaticLint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestShape {
    StaticLint,
    TwiceReduceCompareByHash,
    FingerprintCompare,
    AbiGoldenVectors,
    QemuInertCompare,
    PatchMicrotests,
    ResponsivenessBound,
    E2eDeterminism,
    DivergenceBisect,
    AdversarialCompare,
}

#[derive(Clone, Copy, Debug)]
struct GateTestingStandard {
    gate: &'static str,
    owner_packages: &'static [&'static str],
    layers: &'static [Layer],
    shape: TestShape,
    backend: TestBackend,
}

#[derive(Clone, Copy, Debug)]
struct CrateTestingOwnership {
    package: &'static str,
    gates: &'static [&'static str],
}

const GATE_TESTING_STANDARDS: &[GateTestingStandard] = &[
    GateTestingStandard {
        gate: "gate:harness-lint",
        owner_packages: &["crucible-harness"],
        layers: &[Layer::CrossCutting],
        shape: TestShape::StaticLint,
        backend: TestBackend::StaticLint,
    },
    GateTestingStandard {
        gate: "gate:layer0-determinism",
        owner_packages: &["crucible-sim", "crucible-assert", "crucible"],
        layers: &[Layer::L0, Layer::L3],
        shape: TestShape::TwiceReduceCompareByHash,
        backend: TestBackend::InProcess,
    },
    GateTestingStandard {
        gate: "gate:single-vm-fingerprint",
        owner_packages: &["crucible-qemu", "crucible-qemu-plugin", "crucible-guest"],
        layers: &[Layer::L2],
        shape: TestShape::FingerprintCompare,
        backend: TestBackend::RealQemu,
    },
    GateTestingStandard {
        gate: "gate:layer1-injection",
        owner_packages: &["crucible-device", "crucible-protocol", "crucible-shmem"],
        layers: &[Layer::L1],
        shape: TestShape::TwiceReduceCompareByHash,
        backend: TestBackend::SimDouble,
    },
    GateTestingStandard {
        gate: "gate:abi-conformance",
        owner_packages: &[
            "crucible-harness",
            "crucible-shmem",
            "crucible-protocol",
            "crucible-api",
        ],
        layers: &[Layer::L1, Layer::L4, Layer::CrossCutting],
        shape: TestShape::AbiGoldenVectors,
        backend: TestBackend::InProcess,
    },
    GateTestingStandard {
        gate: "gate:replay-oracle",
        owner_packages: &["crucible"],
        layers: &[Layer::L3],
        shape: TestShape::TwiceReduceCompareByHash,
        backend: TestBackend::SimDouble,
    },
    GateTestingStandard {
        gate: "gate:content-address",
        owner_packages: &["crucible", "crucible-sim"],
        layers: &[Layer::L0, Layer::L3],
        shape: TestShape::TwiceReduceCompareByHash,
        backend: TestBackend::InProcess,
    },
    GateTestingStandard {
        gate: "gate:scheduler-liveness",
        owner_packages: &["crucible"],
        layers: &[Layer::L3],
        shape: TestShape::TwiceReduceCompareByHash,
        backend: TestBackend::SimDouble,
    },
    GateTestingStandard {
        gate: "gate:control-responsive",
        owner_packages: &["crucible-session", "crucible-api", "crucible-daemon"],
        layers: &[Layer::L4],
        shape: TestShape::ResponsivenessBound,
        backend: TestBackend::SimDouble,
    },
    GateTestingStandard {
        gate: "gate:any-guest",
        owner_packages: &["crucible-qemu"],
        layers: &[Layer::L2],
        shape: TestShape::FingerprintCompare,
        backend: TestBackend::RealQemu,
    },
    GateTestingStandard {
        gate: "gate:qemu-inert",
        owner_packages: &["crucible-qemu", "crucible-qemu-plugin"],
        layers: &[Layer::L2],
        shape: TestShape::QemuInertCompare,
        backend: TestBackend::RealQemu,
    },
    GateTestingStandard {
        gate: "gate:patch-microtests",
        owner_packages: &["crucible-qemu-plugin"],
        layers: &[Layer::L2],
        shape: TestShape::PatchMicrotests,
        backend: TestBackend::RealQemu,
    },
    GateTestingStandard {
        gate: "gate:divergence-bisect",
        owner_packages: &["crucible-harness"],
        layers: &[Layer::CrossCutting],
        shape: TestShape::DivergenceBisect,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:adversarial-determinism",
        owner_packages: &["crucible-harness"],
        layers: &[Layer::CrossCutting],
        shape: TestShape::AdversarialCompare,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:e2e-determinism",
        owner_packages: &["crucible-harness", "crucible-cli"],
        layers: &[Layer::L4, Layer::CrossCutting],
        shape: TestShape::E2eDeterminism,
        backend: TestBackend::Mixed,
    },
];

const CRATE_TESTING_OWNERSHIP: &[CrateTestingOwnership] = &[
    CrateTestingOwnership {
        package: "crucible-sim",
        gates: &["gate:layer0-determinism", "gate:content-address"],
    },
    CrateTestingOwnership {
        package: "crucible-assert",
        gates: &["gate:layer0-determinism"],
    },
    CrateTestingOwnership {
        package: "crucible-shmem",
        gates: &["gate:abi-conformance", "gate:layer1-injection"],
    },
    CrateTestingOwnership {
        package: "crucible-protocol",
        gates: &["gate:layer1-injection", "gate:abi-conformance"],
    },
    CrateTestingOwnership {
        package: "crucible-device",
        gates: &["gate:layer1-injection"],
    },
    CrateTestingOwnership {
        package: "crucible-qemu",
        gates: &[
            "gate:single-vm-fingerprint",
            "gate:any-guest",
            "gate:qemu-inert",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-qemu-plugin",
        gates: &[
            "gate:single-vm-fingerprint",
            "gate:qemu-inert",
            "gate:patch-microtests",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-guest",
        gates: &["gate:single-vm-fingerprint"],
    },
    CrateTestingOwnership {
        package: "crucible",
        gates: &[
            "gate:layer0-determinism",
            "gate:replay-oracle",
            "gate:content-address",
            "gate:scheduler-liveness",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-session",
        gates: &["gate:control-responsive"],
    },
    CrateTestingOwnership {
        package: "crucible-api",
        gates: &["gate:control-responsive", "gate:abi-conformance"],
    },
    CrateTestingOwnership {
        package: "crucible-daemon",
        gates: &["gate:control-responsive"],
    },
    CrateTestingOwnership {
        package: "crucible-cli",
        gates: &["gate:e2e-determinism"],
    },
    CrateTestingOwnership {
        package: "crucible-harness",
        gates: &[
            "gate:harness-lint",
            "gate:abi-conformance",
            "gate:divergence-bisect",
            "gate:adversarial-determinism",
            "gate:e2e-determinism",
        ],
    },
];

const FLAKY_ESCAPE_PATTERNS: &[&str] = &[
    "flaky",
    "retry",
    "rerun",
    "thread::sleep",
    "std::thread::sleep",
];
const HASH_COMPARE_GATES: &[&str] = &[
    "gate:layer0-determinism",
    "gate:layer1-injection",
    "gate:replay-oracle",
    "gate:content-address",
    "gate:scheduler-liveness",
];
const TWICE_REDUCE_HELPER: &str = "assert_twice_reduce_canonical_digest(";
const DUMP_COMPARE_PATTERNS: &[&str] = &["human_formatted_dump", "formatted_dump", "dump()"];

#[test]
fn gate_targets_follow_per_layer_testing_standards() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let source_overrides = gate_target_source_overrides(&root)?;
    let mut failures = testing_standard_failures(gate_targets(), &source_overrides);
    failures.extend(testing_standard_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible testing-standard lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn gate_target_sources_treat_flaky_as_failing() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut failures = Vec::new();

    for source in crucible_test_sources(&root)? {
        let content = fs::read_to_string(&source.path)?;
        failures.extend(flaky_escape_failures(
            &source.package,
            &source.test_target,
            &content,
        ));
    }

    failures.extend(testing_source_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible flaky-is-failing lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

fn testing_standard_failures(
    targets: &[GateTargetSpec],
    source_overrides: &GateSourceOverrides,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut targets_by_gate: BTreeMap<&str, Vec<&GateTargetSpec>> = BTreeMap::new();
    let mut gates_by_package: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for target in targets {
        targets_by_gate.entry(target.gate).or_default().push(target);
        gates_by_package
            .entry(target.package)
            .or_default()
            .insert(target.gate);

        let Some(standard) = standard_for_gate(target.gate) else {
            failures.push(format!(
                "{}:{} has no per-layer testing standard",
                target.package, target.test_target
            ));
            continue;
        };

        let Some(layer) = package_layer(target.package) else {
            failures.push(format!(
                "{}:{} has unknown package layer",
                target.package, target.test_target
            ));
            continue;
        };

        if !standard.layers.contains(&layer) {
            failures.push(format!(
                "{}:{} covers {} from wrong layer {:?}; allowed layers are {:?}",
                target.package, target.test_target, target.gate, layer, standard.layers
            ));
        }

        failures.extend(backend_failures(target, standard));

        if let Some(content) = source_overrides.get(&(target.package, target.test_target)) {
            failures.extend(source_shape_failures(target, standard, content.as_str()));
            failures.extend(flaky_escape_failures(
                target.package,
                target.test_target,
                content.as_str(),
            ));
        }
    }

    for ownership in CRATE_TESTING_OWNERSHIP {
        let actual = gates_by_package
            .get(ownership.package)
            .cloned()
            .unwrap_or_default();
        let expected: BTreeSet<&str> = ownership.gates.iter().copied().collect();

        for required in expected.difference(&actual) {
            failures.push(format!(
                "{} missing crate-owned layer gate {}",
                ownership.package, required
            ));
        }
    }

    for standard in GATE_TESTING_STANDARDS {
        let actual: BTreeSet<&str> = targets_by_gate
            .get(standard.gate)
            .into_iter()
            .flatten()
            .map(|target| target.package)
            .collect();
        let expected: BTreeSet<&str> = standard.owner_packages.iter().copied().collect();

        if actual != expected {
            failures.push(format!(
                "{} owner package mismatch: expected {:?}, found {:?}",
                standard.gate, expected, actual
            ));
        }

        if HASH_COMPARE_GATES.contains(&standard.gate)
            && standard.shape != TestShape::TwiceReduceCompareByHash
        {
            failures.push(format!(
                "{} must use the twice-reduce compare-by-hash shape",
                standard.gate
            ));
        }
    }

    failures
}

fn backend_failures(target: &GateTargetSpec, standard: &GateTestingStandard) -> Vec<String> {
    let mut failures = Vec::new();

    if standard.backend == TestBackend::SimDouble
        && matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} must use SimDouble/in-process coverage, not an L2 real-QEMU owner",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::RealQemu
        && !matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} is a real-QEMU-only gate but is not owned by an L2 crate",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble
        && target.package == "crucible"
        && !target.required_features.contains(&"test-double")
    {
        failures.push(format!(
            "{}:{} must run with --features test-double for SimDouble coverage",
            target.package, target.test_target
        ));
    }

    failures
}

fn flaky_escape_failures(package: &str, test_target: &str, content: &str) -> Vec<String> {
    let lower = content.to_ascii_lowercase();
    FLAKY_ESCAPE_PATTERNS
        .iter()
        .filter(|pattern| lower.contains(**pattern))
        .map(|pattern| {
            format!("{package}:{test_target} contains flaky-test escape pattern `{pattern}`")
        })
        .collect()
}

fn source_shape_failures(
    target: &GateTargetSpec,
    standard: &GateTestingStandard,
    content: &str,
) -> Vec<String> {
    if target.placeholder {
        return Vec::new();
    }
    if target.package == "crucible-shmem" && target.gate == "gate:layer1-injection" {
        return Vec::new();
    }

    let code = scrub_comments_and_strings(content);
    let lower = code.to_ascii_lowercase();
    let mut failures = Vec::new();

    if standard.shape == TestShape::TwiceReduceCompareByHash && !code.contains(TWICE_REDUCE_HELPER)
    {
        failures.push(format!(
            "{}:{} must call {TWICE_REDUCE_HELPER} to drive twice and compare canonical digests",
            target.package, target.test_target,
        ));
    }

    if DUMP_COMPARE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        failures.push(format!(
            "{}:{} must compare canonical digests, not formatted dumps",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble && !code.contains("SimDouble") {
        failures.push(format!(
            "{}:{} must exercise the SimDouble backend",
            target.package, target.test_target
        ));
    }

    failures
}

fn standard_for_gate(gate: &str) -> Option<&'static GateTestingStandard> {
    GATE_TESTING_STANDARDS
        .iter()
        .find(|standard| standard.gate == gate)
}

fn package_layer(package: &str) -> Option<Layer> {
    match package {
        "crucible-sim" | "crucible-assert" => Some(Layer::L0),
        "crucible-shmem" | "crucible-protocol" | "crucible-device" => Some(Layer::L1),
        "crucible-qemu" | "crucible-qemu-plugin" | "crucible-guest" => Some(Layer::L2),
        "crucible" => Some(Layer::L3),
        "crucible-session" | "crucible-api" | "crucible-daemon" | "crucible-cli" => Some(Layer::L4),
        "crucible-harness" => Some(Layer::CrossCutting),
        _ => None,
    }
}

fn testing_standard_regression_failures() -> Vec<String> {
    let synthetic_targets = [
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible-qemu",
            test_target: "gate_replay_oracle",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:unknown",
            package: "crucible-harness",
            test_target: "unknown_gate",
            required_features: &[],
            placeholder: true,
        },
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible",
            test_target: "gate_replay_oracle",
            required_features: &["test-double"],
            placeholder: false,
        },
    ];
    let source_overrides = BTreeMap::from([(
        ("crucible", "gate_replay_oracle"),
        r#"
            // assert_twice_reduce_canonical_digest(canonical_digest);
            // SimDouble
            #[test]
            fn bad() {
                assert_twice_reduce_canonical_digest(|| canonical_digest());
                assert_eq!(human_formatted_dump(), human_formatted_dump());
            }
        "#
        .to_string(),
    )]);
    let findings = testing_standard_failures(&synthetic_targets, &source_overrides);
    let mut failures = Vec::new();

    if !findings
        .iter()
        .any(|finding| finding.contains("wrong layer"))
    {
        failures.push(
            "testing-standard regression failed to reject higher/lower layer ownership drift"
                .to_string(),
        );
    }
    if !findings.iter().any(|finding| finding.contains("SimDouble")) {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble ownership".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("no per-layer testing standard"))
    {
        failures
            .push("testing-standard regression failed to reject unknown gate standard".to_string());
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("canonical digests"))
    {
        failures.push(
            "testing-standard regression failed to reject non-hash determinism assertions"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("SimDouble backend"))
    {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble body coverage"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("crucible-assert missing crate-owned layer gate"))
    {
        failures.push(
            "testing-standard regression failed to reject missing per-crate ownership".to_string(),
        );
    }

    failures
}

fn testing_source_regression_failures() -> Vec<String> {
    let findings = flaky_escape_failures(
        "crucible",
        "gate_replay_oracle",
        r#"
            #[test]
            fn bad() {
                retry_until_not_flaky();
            }
        "#,
    );

    if findings.len() >= 2 {
        Vec::new()
    } else {
        vec!["testing-standard regression failed to reject flaky/retry escapes".to_string()]
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|path| path.parent()) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

#[derive(Clone, Debug)]
struct TestSource {
    package: String,
    test_target: String,
    path: PathBuf,
}

fn crucible_test_sources(root: &Path) -> Result<Vec<TestSource>, Box<dyn Error>> {
    let crates_dir = root.join("crates");
    let mut sources = Vec::new();

    for entry in fs::read_dir(&crates_dir)? {
        let entry = entry?;
        let package = entry.file_name().to_string_lossy().into_owned();
        if !package.starts_with("crucible") {
            continue;
        }

        let mut paths = Vec::new();
        collect_rust_sources(&entry.path().join("tests"), &mut paths)?;
        collect_unit_test_sources(&entry.path().join("src"), &mut paths)?;

        for path in paths {
            let test_target = test_target_name(&entry.path(), &path);
            if package == "crucible-harness"
                && matches!(
                    test_target.as_str(),
                    "testing_standards" | "tests/testing_standards"
                )
            {
                continue;
            }

            sources.push(TestSource {
                package: package.clone(),
                test_target,
                path,
            });
        }
    }

    sources.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(sources)
}

fn gate_target_source_overrides(root: &Path) -> Result<GateSourceOverrides, Box<dyn Error>> {
    let mut sources = BTreeMap::new();

    for target in gate_targets() {
        let path = root
            .join("crates")
            .join(target.package)
            .join("tests")
            .join(format!("{}.rs", target.test_target));
        sources.insert(
            (target.package, target.test_target),
            fs::read_to_string(path)?,
        );
    }

    Ok(sources)
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }

    Ok(())
}

fn collect_unit_test_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    let mut candidates = Vec::new();
    collect_rust_sources(dir, &mut candidates)?;

    let has_unit_test_module = candidates.iter().any(|path| {
        fs::read_to_string(path)
            .is_ok_and(|content| content.contains("#[cfg(test") || content.contains("mod tests"))
    });

    if has_unit_test_module {
        sources.extend(candidates);
    }

    Ok(())
}

fn test_target_name(package_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(package_dir) {
        Ok(relative) => relative
            .with_extension("")
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => path
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
}

fn scrub_comments_and_strings(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else {
                    out.push(ch);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = ScannerState::Code;
                } else {
                    out.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    out.push(' ');
                    out.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    out
}

#[derive(Clone, Copy, Debug)]
enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}
