//! Fingerprint and translation-prefetch launch-option cases.

use super::*;

pub(super) fn validated_whitebox_setup() -> crucible_qemu::QemuWhiteboxSetupValidation {
    validate_x86_whitebox_hmp_mtree(
        "FlatView #2\n AS \"I/O\", root: io\n  00000000000000e0-00000000000000ef (prio 0, i/o): io @00000000000000e0\n",
    )
    .unwrap_or_else(|error| panic!("test white-box setup validation failed: {error}"))
}

#[test]
fn fingerprint_plugin_switch_is_emitted_only_when_enabled() {
    let base = QemuLaunchPluginConfig::new(
        "/nix/store/66666666666666666666666666666666-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    );
    let fault_hash = lowercase_hex(&base.fault_node_hash());
    // Disabled default is byte-identical to the pre-fingerprint ABI: no key.
    assert_eq!(
        base.plugin_args_raw(),
        format!(
            "simfd=3,slot=0,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=off,coverage=off"
        )
    );
    assert_eq!(
        base.clone()
            .with_fingerprint(QemuLaunchPluginSwitch::Off)
            .plugin_args_raw(),
        base.plugin_args_raw()
    );
    // Enabled appends the fingerprint key after coverage.
    assert_eq!(
        base.clone()
            .with_fingerprint(QemuLaunchPluginSwitch::On)
            .plugin_args_raw(),
        format!(
            "simfd=3,slot=0,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=off,coverage=off,fingerprint=on"
        )
    );
    assert_eq!(
        base.with_fingerprint(QemuLaunchPluginSwitch::On)
            .with_fingerprint_oracle(QemuLaunchPluginSwitch::On)
            .plugin_args_raw(),
        format!(
            "simfd=3,slot=0,fault_node_hash={fault_hash},shmemfd=4,wakefd=5,whitebox=off,coverage=off,fingerprint=on,fingerprint_oracle=on"
        )
    );
}

#[test]
fn translation_prefetch_experiment_is_explicit_and_default_off() {
    let default_command = default_launch_command();
    assert!(
        default_command
            .args()
            .windows(2)
            .any(|window| { window == ["-accel", "sim,thread=single"] })
    );
    assert!(
        default_command
            .args()
            .iter()
            .all(|argument| !argument.contains("crucible-translation-prefetch"))
    );

    let enabled_command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
    )
    .with_translation_prefetch_experiment(true, "/tmp/translation-prefetch.report")
    .build()
    .unwrap_or_else(|error| panic!("translation-prefetch launch should build: {error}"));
    assert!(enabled_command.args().windows(2).any(|window| {
        window
            == [
                "-accel",
                "sim,thread=single,crucible-translation-prefetch=on,crucible-translation-prefetch-report=/tmp/translation-prefetch.report",
            ]
    }));
    assert_eq!(
        enabled_command.vm_launch_hash_material(),
        default_command.vm_launch_hash_material(),
        "the gate-only host mechanism must not alter VM scenario content"
    );

    for invalid_path in ["relative.report", "/tmp/report,with-comma"] {
        assert_eq!(
            QemuLaunchCommandBuilder::new(
                default_profile(),
                default_vm_config(),
                default_qemu_binary(),
                default_plugin_config(),
            )
            .with_translation_prefetch_experiment(true, invalid_path)
            .build(),
            Err(QemuLaunchCommandError::InvalidTranslationPrefetchReportPath)
        );
    }
}
