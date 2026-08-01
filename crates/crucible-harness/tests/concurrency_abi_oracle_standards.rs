//! Checks the RFC-0010 concurrency, ABI, and replay-oracle test standards.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::gate_targets::{GateTargetSpec, gate_targets};

type GateSourceOverrides = BTreeMap<(&'static str, &'static str), String>;

#[path = "support/concurrency_abi_oracle_standards.rs"]
mod support;

use support::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AdvancedTestKind {
    SpscConcurrency,
    InjectionDeterminism,
    BoundaryAbi,
    WireFuzzing,
    ReplayOracle,
}

#[derive(Clone, Copy, Debug)]
struct AdvancedTestStandard {
    id: &'static str,
    gate: &'static str,
    package: &'static str,
    test_target: &'static str,
    required_features: &'static [&'static str],
    kind: AdvancedTestKind,
    required_markers: &'static [&'static str],
}

const SPSC_RING_MARKERS: &[&str] = &[
    "assert_spsc_ring_exhaustive_ordering_model(",
    "assert_spsc_ring_exhaustive_trace_properties(",
    "NoLostFrame",
    "NoDuplicatedFrame",
    "FifoOrder",
    "FullEmpty",
    "Wraparound",
];

const CONCURRENT_SOURCE_CONTEXT_MARKERS: &[&str] =
    &["spsc", "ring", "queue", "lockfree", "lock-free", "atomic"];
const ATOMIC_PRIMITIVE_MARKERS: &[&str] = &[
    "Atomic",
    "core::sync::atomic",
    "std::sync::atomic",
    "compare_exchange",
    "fetch_add",
    "fetch_sub",
    "fetch_or",
    "fetch_and",
    "fetch_xor",
    "fetch_update",
];
const CONTEXTUAL_ATOMIC_MARKERS: &[&str] = &["Ordering::", ".load(", ".store(", ".swap("];
const UNSAFE_PRIMITIVE_MARKERS: &[&str] =
    &["unsafe {", "unsafe fn", "unsafe impl", "unsafe extern"];

const ABI_MARKERS: &[&str] = &[
    "assert_frozen_golden_vectors(",
    "assert_decode_encode_roundtrip(",
    "assert_abi_version_field(",
    "assert_version_bump_regenerates_vectors(",
    "assert_structure_aware_fuzz_corpus(",
    "regression_corpus",
];

const HARNESS_ABI_MARKERS: &[&str] = &[
    "assert_frozen_golden_vectors(",
    "assert_decode_encode_roundtrip(",
    "assert_abi_version_field(",
    "assert_version_bump_regenerates_vectors(",
    "assert_structure_aware_fuzz_corpus(",
    "ShmemLayoutAbi",
    "GuestHostProtocolAbi",
    "ControlPlaneRpcAbi",
];

const PROTOCOL_CODEC_FUZZ_MARKERS: &[&str] = &[
    "assert_protocol_codec_fuzz_corpus(",
    "assert_decode_encode_roundtrip(",
    "assert_clean_reject_or_deterministic_decode(",
    "regression_corpus",
];

const DEVICE_INJECTION_MARKERS: &[&str] = &[
    "run_two_vm_injection",
    "struct ObservedInjection",
    "producer_host_tick",
    "HostStep::Observe",
    "assert_eq!(producer_skewed, consumer_skewed);",
    "assert_ne!(producer_skewed, consumer_skewed);",
];

const REPLAY_ORACLE_MARKERS: &[&str] = &[
    "assert_replay_oracle_fixed_checkpoint_corpus(",
    "struct MaterializedCheckpoint",
    "fn materialize_fat_checkpoint(",
    "fn schedule_delta(",
    "fn replay_schedule(",
    "assert_replay_oracle_rejects_corrupt_configuration_metadata(",
    "assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(",
    "assert_replay_oracle_excludes_observational_entries(",
    "assert_replay_oracle_reports_first_mismatch(",
    "assert_twice_reduce_canonical_digest(",
    "SimDouble",
];

const ADVANCED_TEST_STANDARDS: &[AdvancedTestStandard] = &[
    AdvancedTestStandard {
        id: "all-boundary-abi-conformance",
        gate: "gate:abi-conformance",
        package: "crucible-harness",
        test_target: "gate_abi_conformance",
        required_features: &[],
        kind: AdvancedTestKind::BoundaryAbi,
        required_markers: HARNESS_ABI_MARKERS,
    },
    AdvancedTestStandard {
        id: "spsc-ring-concurrency",
        gate: "gate:layer1-injection",
        package: "crucible-shmem",
        test_target: "gate_layer1_injection",
        required_features: &[],
        kind: AdvancedTestKind::SpscConcurrency,
        required_markers: SPSC_RING_MARKERS,
    },
    AdvancedTestStandard {
        id: "shmem-layout-abi",
        gate: "gate:abi-conformance",
        package: "crucible-shmem",
        test_target: "gate_abi_conformance",
        required_features: &[],
        kind: AdvancedTestKind::BoundaryAbi,
        required_markers: ABI_MARKERS,
    },
    AdvancedTestStandard {
        id: "guest-host-protocol-abi",
        gate: "gate:abi-conformance",
        package: "crucible-protocol",
        test_target: "gate_abi_conformance",
        required_features: &[],
        kind: AdvancedTestKind::BoundaryAbi,
        required_markers: ABI_MARKERS,
    },
    AdvancedTestStandard {
        id: "control-plane-rpc-abi",
        gate: "gate:abi-conformance",
        package: "crucible-api",
        test_target: "gate_abi_conformance",
        required_features: &[],
        kind: AdvancedTestKind::BoundaryAbi,
        required_markers: ABI_MARKERS,
    },
    AdvancedTestStandard {
        id: "protocol-codec-fuzzing",
        gate: "gate:abi-conformance",
        package: "crucible-protocol",
        test_target: "gate_abi_conformance",
        required_features: &[],
        kind: AdvancedTestKind::WireFuzzing,
        required_markers: PROTOCOL_CODEC_FUZZ_MARKERS,
    },
    AdvancedTestStandard {
        id: "device-injection-determinism",
        gate: "gate:layer1-injection",
        package: "crucible-device",
        test_target: "gate_layer1_injection",
        required_features: &[],
        kind: AdvancedTestKind::InjectionDeterminism,
        required_markers: DEVICE_INJECTION_MARKERS,
    },
    AdvancedTestStandard {
        id: "replay-oracle-fixed-corpus",
        gate: "gate:replay-oracle",
        package: "crucible",
        test_target: "gate_replay_oracle",
        required_features: &["test-double"],
        kind: AdvancedTestKind::ReplayOracle,
        required_markers: REPLAY_ORACLE_MARKERS,
    },
];

#[test]
fn gate_targets_follow_concurrency_abi_and_oracle_standards() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let source_overrides = gate_target_source_overrides(&root)?;
    let mut failures = advanced_standard_failures(gate_targets(), &source_overrides);
    failures.extend(spsc_ring_unsafe_without_model_failures(
        &root,
        gate_targets(),
    )?);
    failures.extend(advanced_standard_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible concurrency/ABI/oracle standard lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn standards_cover_the_required_abi_and_oracle_surface() {
    let boundary_abis: BTreeSet<&str> = ADVANCED_TEST_STANDARDS
        .iter()
        .filter(|standard| standard.kind == AdvancedTestKind::BoundaryAbi)
        .map(|standard| standard.id)
        .collect();
    let modes: BTreeSet<AdvancedTestKind> = ADVANCED_TEST_STANDARDS
        .iter()
        .map(|standard| standard.kind)
        .collect();

    assert_eq!(
        boundary_abis,
        BTreeSet::from([
            "all-boundary-abi-conformance",
            "shmem-layout-abi",
            "guest-host-protocol-abi",
            "control-plane-rpc-abi",
        ])
    );
    assert_eq!(
        modes,
        BTreeSet::from([
            AdvancedTestKind::SpscConcurrency,
            AdvancedTestKind::InjectionDeterminism,
            AdvancedTestKind::BoundaryAbi,
            AdvancedTestKind::WireFuzzing,
            AdvancedTestKind::ReplayOracle,
        ])
    );
}
