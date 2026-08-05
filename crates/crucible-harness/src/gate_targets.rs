//! Canonical mapping from gate names to isolable Cargo test targets.
//!
//! RFC-0010 file 27 requires each per-layer determinism gate to have an
//! addressable test target in the crate that owns it. Most real gate bodies are
//! intentionally still later-phase work; this map names the targets without
//! marking those gates implemented.

/// A named Cargo test target for a determinism gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTargetSpec {
    /// Canonical RFC gate name.
    pub gate: &'static str,
    /// Cargo package that owns the test target.
    pub package: &'static str,
    /// Cargo integration-test target name, without `.rs`.
    pub test_target: &'static str,
    /// Features required when running this target.
    pub required_features: &'static [&'static str],
    /// Whether the target is still a red placeholder.
    pub placeholder: bool,
}

/// Cargo test targets for the RFC-0010 crate-structure gate map.
pub const GATE_TARGETS: &[GateTargetSpec] = &[
    GateTargetSpec {
        gate: "gate:harness-lint",
        package: "crucible-harness",
        test_target: "harness_lint",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:license-boundary",
        package: "crucible-harness",
        test_target: "gate_license_boundary",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer0-determinism",
        package: "crucible-sim",
        test_target: "gate_layer0_determinism",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer0-determinism",
        package: "crucible-assert",
        test_target: "gate_layer0_determinism",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer0-determinism",
        package: "crucible",
        test_target: "gate_layer0_determinism",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:single-vm-fingerprint",
        package: "crucible",
        test_target: "gate_single_vm_fingerprint",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:single-vm-fingerprint",
        package: "crucible-qemu",
        test_target: "gate_single_vm_fingerprint",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:single-vm-fingerprint",
        package: "crucible-qemu-plugin",
        test_target: "gate_single_vm_fingerprint",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:single-vm-fingerprint",
        package: "crucible-guest",
        test_target: "gate_single_vm_fingerprint",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer1-injection",
        package: "crucible-device",
        test_target: "gate_layer1_injection",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer1-injection",
        package: "crucible-protocol",
        test_target: "gate_layer1_injection",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:layer1-injection",
        package: "crucible-shmem",
        test_target: "gate_layer1_injection",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-harness",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-shmem",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-protocol",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-api",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-qemu-plugin",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible-guest",
        test_target: "gate_abi_conformance",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:abi-conformance",
        package: "crucible",
        test_target: "gate_abi_conformance",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:replay-oracle",
        package: "crucible",
        test_target: "gate_replay_oracle",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:content-address",
        package: "crucible",
        test_target: "gate_content_address",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:content-address",
        package: "crucible-sim",
        test_target: "gate_content_address",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:scheduler-liveness",
        package: "crucible",
        test_target: "gate_scheduler_liveness",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:control-responsive",
        package: "crucible-session",
        test_target: "gate_control_responsive",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:control-responsive",
        package: "crucible-api",
        test_target: "gate_control_responsive",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:control-responsive",
        package: "crucible-daemon",
        test_target: "gate_control_responsive",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:any-guest",
        package: "crucible-qemu",
        test_target: "gate_any_guest",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:qemu-inert",
        package: "crucible-qemu",
        test_target: "gate_qemu_inert",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:qemu-inert",
        package: "crucible-qemu-plugin",
        test_target: "gate_qemu_inert",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:patch-microtests",
        package: "crucible-qemu-plugin",
        test_target: "gate_patch_microtests",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:divergence-bisect",
        package: "crucible-harness",
        test_target: "gate_divergence_bisect",
        required_features: &[],
        placeholder: false,
    },
    // The canonical adversarial-determinism gate is the crucible-side
    // real-simulator test that drives the real `SingleScheduler` through the
    // host-adversary matrix, not the harness-side mock corpus.
    GateTargetSpec {
        gate: "gate:adversarial-determinism",
        package: "crucible",
        test_target: "gate_adversarial_determinism",
        required_features: &[],
        placeholder: false,
    },
    // The canonical e2e-determinism gate is the crucible-side real-simulator test
    // that anchors serial-vs-concurrent driving to the authoritative `drive_quantum`
    // path, not the harness-side mock artifact.
    GateTargetSpec {
        gate: "gate:e2e-determinism",
        package: "crucible",
        test_target: "gate_e2e_determinism_concurrency",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:e2e-determinism",
        package: "crucible-cli",
        test_target: "gate_e2e_determinism",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:basic-block-coverage",
        package: "crucible",
        test_target: "gate_basic_block_coverage",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:basic-block-coverage",
        package: "crucible-qemu",
        test_target: "gate_basic_block_coverage",
        required_features: &[],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:fleet-equivalence",
        package: "crucible",
        test_target: "gate_fleet_equivalence",
        required_features: &["test-double"],
        placeholder: false,
    },
    GateTargetSpec {
        gate: "gate:campaign-continuity",
        package: "crucible-cas",
        test_target: "gate_campaign_continuity",
        required_features: &[],
        placeholder: false,
    },
    // The perf-bench regression gate runs the harness-owned cost-model
    // assertion pass (SS25.7.1 metrics) with no QEMU present.
    GateTargetSpec {
        gate: "gate:perf-bench",
        package: "crucible-harness",
        test_target: "gate_perf_bench",
        required_features: &[],
        placeholder: false,
    },
];

/// Returns every mapped gate target in RFC table order.
#[must_use]
pub fn gate_targets() -> &'static [GateTargetSpec] {
    GATE_TARGETS
}
