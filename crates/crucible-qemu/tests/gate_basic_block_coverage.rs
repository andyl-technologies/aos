//! Checks `gate:basic-block-coverage` at the QEMU host/plugin boundary.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BasicBlockCoverageConfig, BasicBlockCoverageMode, BlackBoxObservationKind, NodeId,
    basic_block_coverage_map_index,
};
use crucible_protocol::PluginBasicBlockCoverageObservation;
use crucible_qemu::{
    QemuBasicBlockCoverageBridge, QemuCoverageError, QemuCoverageFingerprintRun,
    QemuLaunchPluginConfig, QemuLaunchPluginSwitch, SINGLE_VM_FINGERPRINT_DIGEST_BYTES,
    SingleVmFingerprintSample, SingleVmFingerprintSampleMaterial, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmNvcpuFingerprintMaterial, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, compare_coverage_opt_in_fingerprint_streams,
    initial_single_vm_rolling_fingerprint,
};

#[test]
fn gate_basic_block_coverage_consumes_plugin_protocol_observation() {
    let map_entries = 1024;
    let plugin_map_index = basic_block_coverage_map_index(0x4010, map_entries)
        .unwrap_or_else(|error| panic!("test map index should fold: {error}"));
    let observation =
        PluginBasicBlockCoverageObservation::new(77, 2, 0x4010, 16, plugin_map_index as u64, true)
            .unwrap_or_else(|error| panic!("plugin coverage observation should validate: {error}"));
    let bridge = QemuBasicBlockCoverageBridge::new(
        node("plugin-node"),
        BasicBlockCoverageConfig::new(BasicBlockCoverageMode::On, map_entries),
    )
    .unwrap_or_else(|error| panic!("QEMU coverage bridge should build: {error}"));

    let consumed = bridge
        .consume_plugin_observation(observation)
        .unwrap_or_else(|error| panic!("plugin observation should feed engine consumer: {error}"));

    assert_eq!(consumed.map_index(), plugin_map_index);
    assert_eq!(
        consumed.event().payload().black_box_observation_kind(),
        Some(BlackBoxObservationKind::BasicBlockCoverage)
    );
    assert_eq!(consumed.event().at().ticks, 77);

    let wrong_index = PluginBasicBlockCoverageObservation::new(
        77,
        2,
        0x4010,
        16,
        (plugin_map_index + 1) as u64,
        true,
    )
    .unwrap_or_else(|error| panic!("mismatched plugin index observation should validate: {error}"));
    assert_eq!(
        bridge.consume_plugin_observation(wrong_index),
        Err(QemuCoverageError::PluginMapIndexMismatch {
            plugin_map_index: plugin_map_index + 1,
            engine_map_index: plugin_map_index,
        })
    );
}

#[test]
fn gate_basic_block_coverage_compares_coverage_on_off_fingerprint_streams() {
    let off_plugin = plugin_config(QemuLaunchPluginSwitch::Off);
    let on_plugin = plugin_config(QemuLaunchPluginSwitch::On);
    let off_run = QemuCoverageFingerprintRun::new(off_plugin.clone(), stream(&[1, 2, 3], 9));
    let on_run = QemuCoverageFingerprintRun::new(on_plugin.clone(), stream(&[1, 2, 3], 9));

    assert_ne!(off_run.plugin_argument(), on_run.plugin_argument());
    assert!(off_run.plugin_argument().contains("coverage=off"));
    assert!(on_run.plugin_argument().contains("coverage=on"));

    let report = compare_coverage_opt_in_fingerprint_streams(&off_run, &on_run, 12_288)
        .unwrap_or_else(|error| panic!("coverage opt-in must not change fingerprints: {error}"));

    assert_eq!(report.matching_final_fingerprint, digest(9));
    assert_eq!(
        report.off_plugin_argument,
        off_plugin.qemu_plugin_argument()
    );
    assert_eq!(report.on_plugin_argument, on_plugin.qemu_plugin_argument());

    let changed = QemuCoverageFingerprintRun::new(on_plugin, stream(&[1, 7, 3], 9));
    assert!(matches!(
        compare_coverage_opt_in_fingerprint_streams(&off_run, &changed, 12_288),
        Err(QemuCoverageError::FingerprintMismatch { .. })
    ));
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn plugin_config(coverage: QemuLaunchPluginSwitch) -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/66666666666666666666666666666666-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_whitebox(QemuLaunchPluginSwitch::On)
    .with_coverage(coverage)
}

fn stream(sample_bytes: &[u8], final_byte: u8) -> SingleVmFingerprintStream {
    let samples = samples_from_bytes(sample_bytes);
    SingleVmFingerprintStream::new(digest(1), samples, 12_288, digest(final_byte), 12_288)
        .unwrap_or_else(|error| panic!("test stream should be valid: {error}"))
}

fn samples_from_bytes(sample_bytes: &[u8]) -> Vec<SingleVmFingerprintSample> {
    let definition_digest = digest(1);
    let mut previous = initial_rolling(&definition_digest);
    let mut samples = Vec::new();
    for (index, byte) in sample_bytes.iter().enumerate() {
        let cursor = rr_cursor((index % 2) as u64, index as u64, 8);
        let material = material(index as u64, 4096 * (index as u64 + 1), *byte, cursor);
        let sample = sample_from_material(&definition_digest, &previous, material);
        previous = sample.rolling_fingerprint.clone();
        samples.push(sample);
    }
    samples
}

fn sample_from_material(
    definition_digest: &[u8],
    previous: &[u8],
    material: SingleVmFingerprintSampleMaterial,
) -> SingleVmFingerprintSample {
    SingleVmFingerprintSample::from_material(definition_digest, previous, material)
        .unwrap_or_else(|error| panic!("test sample should be valid: {error}"))
}

fn material(
    seq: u64,
    icount: u64,
    state_byte: u8,
    rr_cursor: SingleVmRoundRobinCursor,
) -> SingleVmFingerprintSampleMaterial {
    SingleVmFingerprintSampleMaterial::new(
        seq,
        "node-a",
        icount,
        SingleVmFingerprintTrigger::Periodic,
        nvcpu_material(state_byte, rr_cursor),
    )
    .unwrap_or_else(|error| panic!("test material should be valid: {error}"))
}

fn nvcpu_material(
    state_byte: u8,
    rr_cursor: SingleVmRoundRobinCursor,
) -> SingleVmNvcpuFingerprintMaterial {
    SingleVmNvcpuFingerprintMaterial::new(
        vec![vcpu_register(0, 0x11), vcpu_register(1, state_byte)],
        rr_cursor,
        digest(0xa1),
        digest(0xd1),
    )
    .unwrap_or_else(|error| panic!("test N-vCPU material should be valid: {error}"))
}

fn vcpu_register(vcpu_id: u64, byte: u8) -> SingleVmVcpuRegisterDigest {
    SingleVmVcpuRegisterDigest::new(vcpu_id, digest(byte), 64, 100 + vcpu_id)
        .unwrap_or_else(|error| panic!("test vCPU register should be valid: {error}"))
}

fn rr_cursor(
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
) -> SingleVmRoundRobinCursor {
    SingleVmRoundRobinCursor::new(current_vcpu, position_in_quantum, rr_switch_quantum, 2)
        .unwrap_or_else(|error| panic!("test RR cursor should be valid: {error}"))
}

fn initial_rolling(definition_digest: &[u8]) -> Vec<u8> {
    initial_single_vm_rolling_fingerprint(definition_digest)
        .unwrap_or_else(|error| panic!("test initial rolling fingerprint should be valid: {error}"))
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; SINGLE_VM_FINGERPRINT_DIGEST_BYTES]
}
