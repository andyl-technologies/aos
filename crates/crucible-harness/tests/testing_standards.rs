//! Checks the RFC-0010 per-layer testing standards.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::gate_targets::{GateTargetSpec, gate_targets};

type GateSourceOverrides = BTreeMap<(&'static str, &'static str), String>;

#[path = "support/testing_standards.rs"]
mod support;

use support::*;

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
    ObservedInjectionIcountVectors,
    FingerprintCompare,
    AbiGoldenVectors,
    QemuInertCompare,
    PatchMicrotests,
    ResponsivenessBound,
    E2eDeterminism,
    DivergenceBisect,
    AdversarialCompare,
    FleetEquivalence,
    CampaignContinuity,
    BasicBlockCoverage,
    PerfBenchRegression,
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
        owner_packages: &[
            "crucible",
            "crucible-qemu",
            "crucible-qemu-plugin",
            "crucible-guest",
        ],
        layers: &[Layer::L2, Layer::L3],
        shape: TestShape::FingerprintCompare,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:layer1-injection",
        owner_packages: &["crucible-device", "crucible-protocol", "crucible-shmem"],
        layers: &[Layer::L1],
        shape: TestShape::ObservedInjectionIcountVectors,
        backend: TestBackend::InProcess,
    },
    GateTestingStandard {
        gate: "gate:abi-conformance",
        owner_packages: &[
            "crucible-harness",
            "crucible-shmem",
            "crucible-protocol",
            "crucible-api",
            "crucible-qemu-plugin",
            "crucible-guest",
            "crucible",
        ],
        layers: &[
            Layer::L1,
            Layer::L2,
            Layer::L3,
            Layer::L4,
            Layer::CrossCutting,
        ],
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
        owner_packages: &["crucible"],
        layers: &[Layer::L3],
        shape: TestShape::AdversarialCompare,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:e2e-determinism",
        owner_packages: &["crucible", "crucible-cli"],
        layers: &[Layer::L3, Layer::L4],
        shape: TestShape::E2eDeterminism,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:basic-block-coverage",
        owner_packages: &["crucible", "crucible-qemu"],
        layers: &[Layer::L2, Layer::L3],
        shape: TestShape::BasicBlockCoverage,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:fleet-equivalence",
        owner_packages: &["crucible"],
        layers: &[Layer::L3],
        shape: TestShape::FleetEquivalence,
        backend: TestBackend::Mixed,
    },
    GateTestingStandard {
        gate: "gate:campaign-continuity",
        owner_packages: &["crucible-cas"],
        layers: &[Layer::L3],
        shape: TestShape::CampaignContinuity,
        backend: TestBackend::InProcess,
    },
    // The perf-bench regression gate runs the harness cost-model substrate with
    // no QEMU; it is cross-cutting (Phase >= L2, after the determinism gates) and
    // is a per-metric regression gate, not a byte-identity compare.
    GateTestingStandard {
        gate: "gate:perf-bench",
        owner_packages: &["crucible-harness"],
        layers: &[Layer::CrossCutting],
        shape: TestShape::PerfBenchRegression,
        backend: TestBackend::InProcess,
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
            "gate:basic-block-coverage",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-qemu-plugin",
        gates: &[
            "gate:single-vm-fingerprint",
            "gate:abi-conformance",
            "gate:qemu-inert",
            "gate:patch-microtests",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-guest",
        gates: &["gate:single-vm-fingerprint", "gate:abi-conformance"],
    },
    CrateTestingOwnership {
        package: "crucible",
        gates: &[
            "gate:layer0-determinism",
            "gate:single-vm-fingerprint",
            "gate:abi-conformance",
            "gate:replay-oracle",
            "gate:content-address",
            "gate:scheduler-liveness",
            "gate:adversarial-determinism",
            "gate:e2e-determinism",
            "gate:fleet-equivalence",
            "gate:basic-block-coverage",
        ],
    },
    CrateTestingOwnership {
        package: "crucible-cas",
        gates: &["gate:campaign-continuity"],
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
            "gate:perf-bench",
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
    let baseline = TestingStandardsBaseline::load(&root)?;
    let mut failures = Vec::new();

    for source in crucible_test_sources(&root)? {
        let content = fs::read_to_string(&source.path)?;
        failures.extend(flaky_escape_failures(
            &source.package,
            &source.test_target,
            &content,
        ));
    }

    let mut failures = baseline.filter_flaky_findings(failures);
    failures.extend(testing_source_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible flaky-is-failing lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}
