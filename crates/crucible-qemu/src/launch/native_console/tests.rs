//! Actual command-builder controls; no emulator or native phase provider runs.

use super::*;
use crate::launch::{
    LaunchProfileCandidate, LivePluginGuestArchitecture, QemuLaunchArtifact, QemuLaunchCommand,
    QemuLaunchCommandBuilder, QemuLaunchPluginConfig, QemuVmLaunchConfig,
};

fn command(vcpus: u16, capture: bool) -> Result<QemuLaunchCommand, QemuLaunchCommandError> {
    let profile = LaunchProfileCandidate::default()
        .with_smp_vcpus(vcpus)
        .try_into_deterministic()
        .unwrap_or_else(|error| panic!("fixed test topology should validate: {error}"));
    let firmware = QemuLaunchArtifact::new(
        crucible::ContentHash::from_bytes(b"fixed firmware fixture"),
        "/nix/store/00000000000000000000000000000000-firmware/rom.bin",
    );
    let vm = QemuVmLaunchConfig::new_firmware_boot("console-vm", firmware);
    let plugin = QemuLaunchPluginConfig::new(
        "/nix/store/00000000000000000000000000000000-plugin/lib/plugin.so",
        3,
    )
    .with_fault_target_node("console-vm")
    .with_process_generation(7);
    let builder = QemuLaunchCommandBuilder::new_for_live_gate(
        profile,
        vm,
        "/nix/store/00000000000000000000000000000000-qemu/bin/qemu-system-x86_64",
        plugin,
        LivePluginGuestArchitecture::X86_64,
    );
    if capture {
        builder.with_console_capture().build()
    } else {
        builder.build()
    }
}

#[test]
fn real_console_command_seals_closed_plan_and_native_backend() -> Result<(), QemuLaunchCommandError>
{
    let command = command(4, true)?;
    let setup = command.plugin_setup_plan();
    let console = setup
        .native_console_plan()
        .unwrap_or_else(|| panic!("capture command must carry a console plan"));
    let plan = console.plan();
    assert_eq!(plan.slot, 3);
    assert_eq!((plan.logical_generation, plan.node_sequence_base), (0, 0));
    assert_eq!(plan.streams.len(), 1);
    let stream = &plan.streams[0];
    assert_eq!(
        (stream.stream, stream.owner_mask, stream.sequence_base),
        (1, 15, 0)
    );
    assert_eq!(stream.device, NativeConsoleDevice::Serial16550);
    assert_eq!(
        stream.device_identity,
        stream.device.fixed_console_identity()
    );
    assert_eq!(
        console.issued_authorization_capacity(),
        ISSUED_AUTHORIZATION_CAPACITY
    );
    assert_eq!(
        console.authorization_allowance(),
        AUTHORIZATION_BYTE_ALLOWANCE
    );
    assert!(
        command
            .args()
            .windows(2)
            .any(|args| args == ["-chardev", NATIVE_CONSOLE_CHARDEV_ARGUMENT])
    );
    assert!(
        command
            .args()
            .windows(2)
            .any(|args| args == ["-serial", "chardev:crucible-console"])
    );
    assert!(
        !command
            .args()
            .iter()
            .any(|arg| arg.contains("crucible-console.sock"))
    );
    let encoded = setup
        .encode()
        .unwrap_or_else(|error| panic!("sealed plan should encode: {error}"));
    assert_eq!(
        command.plugin_setup_plan_digest(),
        *blake3::hash(&encoded).as_bytes()
    );
    Ok(())
}

#[test]
fn real_builder_refuses_console_mask_overflow_without_changing_no_console_profile()
-> Result<(), QemuLaunchCommandError> {
    let full = command(64, true)?;
    assert_eq!(
        full.plugin_setup_plan()
            .native_console_plan()
            .unwrap_or_else(|| panic!("capture plan missing"))
            .plan()
            .streams[0]
            .owner_mask,
        u64::MAX
    );
    assert_eq!(
        command(65, true),
        Err(QemuLaunchCommandError::InvalidNativeConsoleProfile)
    );
    assert!(
        command(65, false)?
            .plugin_setup_plan()
            .native_console_plan()
            .is_none()
    );
    assert_eq!(
        closed_launch_plan(FaultCapabilityScope::X86_64, 0, 0),
        Err(QemuLaunchCommandError::InvalidNativeConsoleProfile)
    );
    Ok(())
}

#[test]
fn closed_arm_plan_uses_pl011_with_exact_full_owner_mask() -> Result<(), QemuLaunchCommandError> {
    let setup = closed_launch_plan(FaultCapabilityScope::Aarch64, 4, 8)?;
    assert_eq!(setup.plan().slot, 8);
    assert_eq!(setup.plan().streams[0].device, NativeConsoleDevice::Pl011);
    assert_eq!(setup.plan().streams[0].owner_mask, 15);
    assert_eq!(
        closed_launch_plan(FaultCapabilityScope::All, 1, 0),
        Err(QemuLaunchCommandError::InvalidNativeConsoleProfile)
    );
    Ok(())
}
