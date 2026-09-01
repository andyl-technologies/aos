//! Tests for live-node launch profiles and gate configuration propagation.

use super::*;

#[test]
fn root_image_launch_material_does_not_fall_back_to_firmware() {
    let config = QemuLiveNodeStepGateConfig::new_with_root_image(
        "/aos/bin/qemu-system-x86_64",
        "/aos/lib/crucible-plugin.so",
        "/aos/kernel",
        "/aos/root.raw",
        "/run/crucible",
    )
    .with_root_image_format(QemuRootImageFormat::Raw);

    let material = vm_launch_config(&config, "vm-a").launch_hash_material();

    assert!(material.contains("root_image_format=raw"));
    assert!(material.contains("/aos/root.raw"));
    assert!(!material.contains("firmware"));
}

#[test]
fn diskless_launch_material_retains_firmware() {
    let config = QemuLiveNodeStepGateConfig::new(
        "/aos/bin/qemu-system-x86_64",
        "/aos/lib/crucible-plugin.so",
        "/aos/kernel",
        "/aos/firmware",
        "/run/crucible",
    );

    let material = vm_launch_config(&config, "vm-a").launch_hash_material();

    assert!(material.contains("/aos/firmware"));
    assert!(!material.contains("root_image="));
}

#[test]
fn coverage_switch_reaches_plugin_and_host_drain_configuration() {
    let config = QemuLiveNodeStepGateConfig::new_with_root_image(
        "/aos/bin/qemu-system-x86_64",
        "/aos/lib/crucible-plugin.so",
        "/aos/kernel",
        "/aos/root.raw",
        "/run/crucible",
    )
    .with_coverage(QemuLaunchPluginSwitch::On);

    assert_eq!(
        live_node_plugin_base(&config).coverage(),
        QemuLaunchPluginSwitch::On
    );
    assert_eq!(
        basic_block_coverage_config(config.coverage),
        BasicBlockCoverageConfig::on()
    );
}

#[test]
fn authored_storage_history_limits_reach_the_plugin_launch_boundary() {
    let limits = FaultResourceLimits {
        storage_completed_history_epochs: 7,
        storage_completed_history_gaps: 9,
        ..FaultResourceLimits::default()
    };
    let config = QemuLiveNodeStepGateConfig::new(
        "/aos/bin/qemu-system-x86_64",
        "/aos/lib/crucible-plugin.so",
        "/aos/kernel",
        "/aos/firmware",
        "/run/crucible",
    )
    .with_fault_resource_limits(limits);

    let plugin = live_node_plugin_base(&config);

    assert_eq!(plugin.storage_completed_history_epochs(), 7);
    assert_eq!(plugin.storage_completed_history_gaps(), 9);
    assert!(
        plugin
            .plugin_args_raw()
            .contains("storage_completed_history_epochs=7,storage_completed_history_gaps=9")
    );
}

#[test]
fn x86_64_launch_profile_pins_q35_qemu64_and_ttys0() {
    let profile = launch_profile_candidate(LivePluginGuestArchitecture::X86_64)
        .try_into_deterministic()
        .unwrap_or_else(|error| panic!("x86_64 profile must validate: {error}"));
    let args = profile.canonical_qemu_args();

    assert!(
        args.windows(2)
            .any(|pair| pair == ["-machine", X86_64_MACHINE_TYPE])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-cpu", X86_64_CPU_MODEL])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-append", X86_64_KERNEL_CMDLINE])
    );
}

#[test]
fn aarch64_launch_profile_pins_virt_cortex_a57_and_ttyama0() {
    let profile = launch_profile_candidate(LivePluginGuestArchitecture::Aarch64)
        .try_into_deterministic()
        .unwrap_or_else(|error| panic!("aarch64 profile must validate: {error}"));
    let args = profile.canonical_qemu_args();

    assert!(
        args.windows(2)
            .any(|pair| pair == ["-machine", AARCH64_MACHINE_TYPE])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-cpu", AARCH64_CPU_MODEL])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-append", AARCH64_KERNEL_CMDLINE])
    );
}
