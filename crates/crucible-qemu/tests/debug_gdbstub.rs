//! Debug gdbstub launch-channel tests.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::ContentHash;
use crucible_qemu::{
    DeterministicLaunchProfile, QemuGdbstubChannelConfig, QemuLaunchArtifact,
    QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig, QemuVmLaunchConfig,
};

#[path = "support/mod.rs"]
mod support;

fn default_profile() -> DeterministicLaunchProfile {
    DeterministicLaunchProfile::conservative_default()
        .unwrap_or_else(|error| panic!("default deterministic launch profile failed: {error}"))
}

fn default_plugin_config() -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_fault_target_node("vm-a")
}

fn default_vm_config() -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new(
        "vm-a",
        artifact(
            "kernel",
            "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        ),
        artifact(
            "root-image",
            "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
        ),
    )
}

fn default_qemu_binary() -> &'static str {
    "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
}

fn artifact(domain: &str, path: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(ContentHash::from_canonical_material(domain, path), path)
}

#[test]
fn debug_gdbstub_launch_does_not_expose_guest_activation_device() {
    let gdbstub = QemuGdbstubChannelConfig::new("unix:debug-rsp.sock,server=on,wait=off")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
        support::x86_fault_requirement("vm-a", "qemu64-x86_64-cpu"),
    )
    .with_gdbstub(gdbstub.clone())
    .build()
    .unwrap_or_else(|error| panic!("debug launch command should build: {error}"));

    assert!(
        command
            .args()
            .windows(2)
            .any(|window| { window == ["-gdb", "unix:debug-rsp.sock,server=on,wait=off",] })
    );
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-plugin"
            && window[1].contains("simfd=3,slot=0,fault_node_hash=")
            && window[1].contains(",shmemfd=4,wakefd=5")
    }));
    assert!(!command.args().iter().any(|argument| {
        argument.contains("crucible-debug-activation")
            || argument.contains("crucible-debug-serial")
            || argument.contains("org.aos.crucible.debug")
    }));
    assert_eq!(command.gdbstub_channel(), Some(&gdbstub));
    assert_eq!(
        command
            .gdbstub_channel()
            .map(QemuGdbstubChannelConfig::qemu_endpoint),
        Some("unix:debug-rsp.sock,server=on,wait=off")
    );
    assert!(gdbstub.mediated_by_crucible());
    assert!(gdbstub.out_of_band());
    assert!(!gdbstub.carries_per_quantum_timing());
    assert!(!gdbstub.carries_frame_data());
}

#[test]
fn debug_guest_activation_endpoint_is_fixed_and_inert() {
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
        support::x86_fault_requirement("vm-a", "qemu64-x86_64-cpu"),
    )
    .with_debug_guest_activation_endpoint()
    .build()
    .unwrap_or_else(|error| panic!("debug launch command should build: {error}"));

    assert!(command.args().windows(2).any(|window| {
        window
            == [
                "-device",
                "virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7",
            ]
    }));
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-chardev"
            && window[1].contains("socket,id=crucible-debug-activation")
            && !window[1].contains("server=")
    }));
    assert!(command.args().windows(2).any(|window| {
        window[0] == "-device"
            && window[1].contains("virtserialport,bus=crucible-debug-serial.0")
            && window[1].contains("name=org.aos.crucible.debug")
    }));
    assert!(
        !command
            .args()
            .iter()
            .any(|argument| argument.contains("CRUCIBLE_DEBUG_AGENT_V1"))
    );
    assert!(
        command
            .vm_launch_hash_material()
            .contains("debug_guest_activation_endpoint=fixed-inert-v1")
    );
}

#[test]
fn debug_gdbstub_rejects_unstable_endpoint_text() {
    assert_eq!(
        QemuGdbstubChannelConfig::new(""),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "qemu_gdbstub_endpoint",
        })
    );
    assert_eq!(
        QemuGdbstubChannelConfig::new("unix:debug-rsp.sock,server=on,wait=off\n"),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "qemu_gdbstub_endpoint",
        })
    );
    assert_eq!(
        QemuGdbstubChannelConfig::new("tcp:127.0.0.1:9001"),
        Err(QemuLaunchCommandError::InvalidGdbstubEndpoint {
            endpoint: String::from("tcp:127.0.0.1:9001"),
        })
    );
    assert_eq!(
        QemuGdbstubChannelConfig::new("unix:../debug-rsp.sock,server=on,wait=off"),
        Err(QemuLaunchCommandError::InvalidGdbstubEndpoint {
            endpoint: String::from("unix:../debug-rsp.sock,server=on,wait=off"),
        })
    );
}
