//! Checks `gate:any-guest` contract wiring for QEMU.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::ContentHash;
use crucible_qemu::{
    DeterministicLaunchProfile, GuestCoreContentMode, LaunchProfileCandidate, LaunchProfileError,
    QemuLaunchArtifact, QemuLaunchCommand, QemuLaunchCommandBuilder, QemuLaunchPluginConfig,
    QemuLaunchPluginSwitch, QemuVmLaunchConfig, SINGLE_VM_FINGERPRINT_DIGEST_BYTES,
    SingleVmFingerprintBisectionError, SingleVmFingerprintBisectionReport,
    SingleVmFingerprintBisectionRequest, SingleVmFingerprintRunError, SingleVmFingerprintRunInputs,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintSample, SingleVmFingerprintSampleMaterial, SingleVmFingerprintScenario,
    SingleVmFingerprintStream, SingleVmFingerprintTrigger, SingleVmHostProfile,
    SingleVmNvcpuFingerprintMaterial, SingleVmRoundRobinCursor, SingleVmVcpuRegisterDigest,
    compare_single_vm_fingerprint_streams, initial_single_vm_rolling_fingerprint,
    run_single_vm_fingerprint_gate,
};

#[test]
fn gate_any_guest_launch_profile_requires_host_side_guest_operation() {
    let profile = LaunchProfileCandidate::default()
        .try_into_deterministic()
        .unwrap_or_else(|error| panic!("default launch profile should be deterministic: {error}"));
    let material = profile.scenario_hash_material();

    assert!(material.contains("disk_image_mode=copy-on-write-overlay"));
    assert!(material.contains("guest_backing_state=byte-identical-genesis"));
    assert!(material.contains("guest_core_content=host-side-only"));

    let error = LaunchProfileCandidate::default()
        .with_guest_core_content(GuestCoreContentMode::GuestInjectedContent)
        .try_into_deterministic()
        .expect_err("any-guest operation must not require in-guest Crucible content");
    assert_eq!(
        error,
        LaunchProfileError::GuestCoreContentRequired {
            mode: GuestCoreContentMode::GuestInjectedContent,
        }
    );
}

#[test]
fn gate_any_guest_whitebox_switch_is_host_plugin_configuration_without_agent_content() {
    let definition_digest = digest(0x10);
    let scenario = SingleVmFingerprintScenario::new(
        "any-guest-stock-linux",
        definition_digest.clone(),
        12_288,
        SingleVmFingerprintRunInputs::new(
            digest(0x20),
            "console=ttyS0",
            digest(0x30),
            digest(0x40),
            digest(0x50),
        )
        .unwrap_or_else(|error| panic!("run inputs should be valid: {error}")),
        SingleVmHostProfile::new(
            "any-guest-host-jitter",
            [
                "host-scheduler-yield-points",
                "stdio-drain-order-variation",
                "timer-poll-rotation",
            ],
        )
        .unwrap_or_else(|error| panic!("host profile should be valid: {error}")),
    )
    .unwrap_or_else(|error| panic!("scenario should be valid: {error}"));
    let stream = stream(&definition_digest, &[11, 29, 47], 83);
    let mut runner = AnyGuestRunner::new(stream.clone());

    let report = run_single_vm_fingerprint_gate(&mut runner, &scenario).unwrap_or_else(|error| {
        panic!("host-plugin off/on no-agent stream contract should hold: {error}")
    });

    assert_eq!(report.sample_count, 3);
    assert_eq!(
        runner.plugin_args,
        vec![
            "simfd=3,slot=0,shmemfd=4,wakefd=5,whitebox=off,coverage=off",
            "simfd=3,slot=0,shmemfd=4,wakefd=5,whitebox=on,coverage=off",
        ]
    );
    compare_single_vm_fingerprint_streams(
        &stream,
        &report.first_stream,
        scenario.run_horizon_icount(),
    )
    .unwrap_or_else(|error| panic!("first stream should be canonical: {error}"));
    compare_single_vm_fingerprint_streams(
        &stream,
        &report.second_stream,
        scenario.run_horizon_icount(),
    )
    .unwrap_or_else(|error| panic!("second stream should be canonical: {error}"));
}

#[test]
fn gate_any_guest_launch_command_keeps_whitebox_as_host_plugin_configuration() {
    let black_box = launch_command(QemuLaunchPluginSwitch::Off);
    let white_box = launch_command(QemuLaunchPluginSwitch::On);

    assert!(
        black_box
            .args()
            .iter()
            .any(|arg| arg.contains("whitebox=off"))
    );
    assert!(
        white_box
            .args()
            .iter()
            .any(|arg| arg.contains("whitebox=on"))
    );
    assert_eq!(
        black_box.vm_launch_hash_material(),
        white_box.vm_launch_hash_material()
    );
}

struct AnyGuestRunner {
    stream: SingleVmFingerprintStream,
    plugin_args: Vec<String>,
}

impl AnyGuestRunner {
    fn new(stream: SingleVmFingerprintStream) -> Self {
        Self {
            stream,
            plugin_args: Vec::new(),
        }
    }
}

impl SingleVmFingerprintRunner for AnyGuestRunner {
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError> {
        let whitebox = match request.ordinal() {
            SingleVmFingerprintRunOrdinal::First => QemuLaunchPluginSwitch::Off,
            SingleVmFingerprintRunOrdinal::Second => QemuLaunchPluginSwitch::On,
        };

        self.plugin_args.push(
            QemuLaunchPluginConfig::new("/nix/store/plugin/lib/libcrucible_qemu_plugin.so", 0)
                .with_whitebox(whitebox)
                .plugin_args_raw(),
        );
        Ok(self.stream.clone())
    }

    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        _request: &SingleVmFingerprintBisectionRequest,
    ) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError> {
        Err(SingleVmFingerprintBisectionError::new(
            "any-guest no-agent test streams should match",
        ))
    }
}

fn launch_command(whitebox: QemuLaunchPluginSwitch) -> QemuLaunchCommand {
    let profile = DeterministicLaunchProfile::conservative_default()
        .unwrap_or_else(|error| panic!("default launch profile should be deterministic: {error}"));
    let vm = QemuVmLaunchConfig::new(
        "any-guest-node",
        QemuLaunchArtifact::new(content_hash(0x41), "/nix/store/aos-kernel/boot/bzImage"),
        QemuLaunchArtifact::new(content_hash(0x42), "/nix/store/aos-root/base.raw"),
    )
    .with_initrd(QemuLaunchArtifact::new(
        content_hash(0x43),
        "/nix/store/aos-initrd/initrd.img",
    ));
    let plugin = QemuLaunchPluginConfig::new("/nix/store/aos-plugin/lib/crucible-qemu.so", 0)
        .with_whitebox(whitebox);

    QemuLaunchCommandBuilder::new(
        profile,
        vm,
        "/nix/store/qemu/bin/qemu-system-x86_64",
        plugin,
    )
    .build()
    .unwrap_or_else(|error| panic!("launch command should build: {error}"))
}

fn stream(
    definition_digest: &[u8],
    sample_bytes: &[u8],
    final_byte: u8,
) -> SingleVmFingerprintStream {
    let mut previous = initial_rolling(definition_digest);
    let mut samples = Vec::new();
    for (index, byte) in sample_bytes.iter().enumerate() {
        let material = sample_material(index as u64, 4096 * (index as u64 + 1), *byte);
        let sample = match SingleVmFingerprintSample::from_material(
            definition_digest,
            &previous,
            material,
        ) {
            Ok(sample) => sample,
            Err(error) => panic!("test sample should be valid: {error}"),
        };
        previous = sample.rolling_fingerprint.clone();
        samples.push(sample);
    }
    SingleVmFingerprintStream::new(
        definition_digest.to_vec(),
        samples,
        12_288,
        digest(final_byte),
        12_288,
    )
    .unwrap_or_else(|error| panic!("test stream should be valid: {error}"))
}

fn sample_material(seq: u64, icount: u64, state_byte: u8) -> SingleVmFingerprintSampleMaterial {
    let nvcpu_fingerprint = SingleVmNvcpuFingerprintMaterial::new(
        vec![vcpu_register(0, state_byte)],
        rr_cursor(),
        digest(0xa1),
        digest(0xd1),
    )
    .unwrap_or_else(|error| panic!("test N-vCPU material should be valid: {error}"));
    SingleVmFingerprintSampleMaterial::new(
        seq,
        "any-guest-node",
        icount,
        SingleVmFingerprintTrigger::Periodic,
        nvcpu_fingerprint,
    )
    .unwrap_or_else(|error| panic!("test sample material should be valid: {error}"))
}

fn vcpu_register(vcpu_id: u64, byte: u8) -> SingleVmVcpuRegisterDigest {
    SingleVmVcpuRegisterDigest::new(vcpu_id, digest(byte), 64, 100 + vcpu_id)
        .unwrap_or_else(|error| panic!("test vCPU register should be valid: {error}"))
}

fn rr_cursor() -> SingleVmRoundRobinCursor {
    SingleVmRoundRobinCursor::new(0, 0, 1, 1)
        .unwrap_or_else(|error| panic!("test RR cursor should be valid: {error}"))
}

fn initial_rolling(definition_digest: &[u8]) -> Vec<u8> {
    initial_single_vm_rolling_fingerprint(definition_digest)
        .unwrap_or_else(|error| panic!("test initial fingerprint should be valid: {error}"))
}

fn content_hash(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; SINGLE_VM_FINGERPRINT_DIGEST_BYTES]
}
