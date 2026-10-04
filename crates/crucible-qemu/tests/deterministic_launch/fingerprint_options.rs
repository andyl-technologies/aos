//! Fingerprint launch-option cases.

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
            "simfd=3,slot=0,fault_node_hash={fault_hash},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4,wakefd=5,whitebox=off,coverage=off"
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
            "simfd=3,slot=0,fault_node_hash={fault_hash},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4,wakefd=5,whitebox=off,coverage=off,fingerprint=on"
        )
    );
}
