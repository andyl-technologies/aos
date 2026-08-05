//! QMP launch-channel tests.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::ContentHash;
use crucible_qemu::{
    DeterministicLaunchProfile, QemuGdbstubChannelConfig, QemuLaunchArtifact,
    QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig,
    QemuPreSpawnLaunchValidationError, QemuQmpChannelConfig, QemuVmLaunchConfig,
    validate_pre_spawn_qemu_launch_args,
};

#[test]
fn qmp_channel_adds_stable_unix_socket_to_launch_command() {
    let qmp = QemuQmpChannelConfig::new("crucible-qmp.sock")
        .unwrap_or_else(|error| panic!("QMP socket config should be valid: {error}"));
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
    )
    .with_qmp(qmp.clone())
    .build()
    .unwrap_or_else(|error| panic!("QMP launch command should build: {error}"));

    assert_eq!(command.qmp_channel(), Some(&qmp));
    assert!(qmp.out_of_band());
    assert!(!qmp.carries_per_quantum_timing());
    assert!(!qmp.carries_frame_data());
    assert_eq!(
        qmp.socket_path("/var/run/crucible-node-7"),
        std::path::PathBuf::from("/var/run/crucible-node-7/crucible-qmp.sock")
    );
    assert!(
        command
            .args()
            .windows(2)
            .any(|window| { window == ["-qmp", "unix:crucible-qmp.sock,server=on,wait=off"] })
    );
    assert!(
        validate_pre_spawn_qemu_launch_args(command.args()).is_ok(),
        "QMP launch command must remain accepted by the pre-spawn determinism validator"
    );

    let material = command.command_line_hash_material();
    let qmp_index = option_index(command.args(), "-qmp");
    assert!(material.contains(&format!("argv[{qmp_index}]=-qmp")));
    assert!(material.contains(&format!(
        "argv[{}]=unix:crucible-qmp.sock,server=on,wait=off",
        qmp_index + 1
    )));
    assert!(!material.contains("/tmp/"));
}

#[test]
fn console_capture_uses_only_the_run_directory_output_socket() {
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
    )
    .with_qmp(
        QemuQmpChannelConfig::new("crucible-qmp.sock")
            .unwrap_or_else(|error| panic!("QMP socket config should be valid: {error}")),
    )
    .with_console_capture()
    .build()
    .unwrap_or_else(|error| panic!("console-capture launch command should build: {error}"));

    assert!(
        command
            .args()
            .windows(2)
            .any(|window| { window == ["-serial", "chardev:crucible-console"] })
    );
    assert!(command.args().windows(2).any(|window| {
        window
            == [
                "-chardev",
                "socket,id=crucible-console,path=crucible-console.sock,server=on,wait=off",
            ]
    }));
    assert!(validate_pre_spawn_qemu_launch_args(command.args()).is_ok());
    let chardevs = command
        .args()
        .windows(2)
        .filter(|window| window[0] == "-chardev")
        .map(|window| window[1].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        chardevs,
        vec!["socket,id=crucible-console,path=crucible-console.sock,server=on,wait=off"]
    );
}

#[test]
fn qmp_and_gdbstub_remain_distinct_out_of_band_launch_channels() {
    let qmp = QemuQmpChannelConfig::new("crucible-qmp.sock")
        .unwrap_or_else(|error| panic!("QMP socket config should be valid: {error}"));
    let gdbstub = QemuGdbstubChannelConfig::new("tcp:127.0.0.1:9001", "127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("gdbstub config should be valid: {error}"));
    let command = QemuLaunchCommandBuilder::new(
        default_profile(),
        default_vm_config(),
        default_qemu_binary(),
        default_plugin_config(),
    )
    .with_qmp(qmp.clone())
    .with_gdbstub(gdbstub.clone())
    .build()
    .unwrap_or_else(|error| panic!("QMP plus gdbstub launch command should build: {error}"));

    let qmp_index = option_index(command.args(), "-qmp");
    let gdb_index = option_index(command.args(), "-gdb");
    assert!(qmp_index < gdb_index);
    assert_eq!(command.qmp_channel(), Some(&qmp));
    assert_eq!(command.gdbstub_channel(), Some(&gdbstub));
    assert_eq!(
        command.args()[qmp_index + 1],
        "unix:crucible-qmp.sock,server=on,wait=off"
    );
    assert_eq!(command.args()[gdb_index + 1], "tcp:127.0.0.1:9001");
    assert!(
        validate_pre_spawn_qemu_launch_args(command.args()).is_ok(),
        "QMP plus gdbstub launch command must remain accepted before spawn"
    );
}

#[test]
fn qmp_channel_rejects_unstable_socket_file_names() {
    assert_eq!(
        QemuQmpChannelConfig::new(""),
        Err(QemuLaunchCommandError::InvalidLaunchText {
            field: "qmp_socket_file_name",
        })
    );
    for file_name in [
        "/tmp/crucible-qmp.sock",
        "../crucible-qmp.sock",
        ".",
        "..",
        "run/crucible-qmp.sock",
        "crucible:qmp.sock",
        "crucible,qmp.sock",
    ] {
        assert_eq!(
            QemuQmpChannelConfig::new(file_name),
            Err(QemuLaunchCommandError::InvalidQmpSocketFileName {
                file_name: file_name.to_owned(),
            })
        );
    }
}

#[test]
fn pre_spawn_validator_rejects_unsafe_qmp_endpoints() {
    assert_qmp_rejected(
        "tcp:127.0.0.1:4444,server=on,wait=off",
        "non-Unix QMP control channel",
    );
    assert_qmp_rejected(
        "unix:crucible-qmp.sock,server=off,wait=off",
        "QMP channel without host-owned server endpoint",
    );
    assert_qmp_rejected(
        "unix:crucible-qmp.sock,server=on,wait=on",
        "QMP channel that can block deterministic launch",
    );
    assert_qmp_rejected(
        "unix:crucible-qmp.sock,server=on,wait=off,abstract=on",
        "unsupported QMP control channel option",
    );
    assert_qmp_rejected("unix:,server=on,wait=off", "unstable QMP socket file name");
    assert_qmp_rejected(
        "unix:/tmp/qmp.sock,server=on,wait=off",
        "unstable QMP socket file name",
    );
    assert_qmp_rejected(
        "unix:../qmp.sock,server=on,wait=off",
        "unstable QMP socket file name",
    );
    assert_qmp_rejected("unix:.,server=on,wait=off", "unstable QMP socket file name");
    assert_qmp_rejected(
        "unix:..,server=on,wait=off",
        "unstable QMP socket file name",
    );
    assert_qmp_rejected(
        "unix:bad\nname.sock,server=on,wait=off",
        "unstable QMP endpoint text",
    );
    assert_qmp_rejected(
        "unix:bad\0name.sock,server=on,wait=off",
        "unstable QMP endpoint text",
    );
}

#[test]
fn pre_spawn_validator_rejects_duplicate_qmp_suboptions() {
    assert_qmp_duplicate_rejected(
        "unix:crucible-qmp.sock,server=on,server=off,wait=off",
        "server",
    );
    assert_qmp_duplicate_rejected("unix:crucible-qmp.sock,server=on,wait=off,wait=on", "wait");
}

#[test]
fn pre_spawn_validator_rejects_duplicate_qmp_channels() {
    let mut args = default_profile().canonical_qemu_args();
    args.extend([
        "-qmp".to_owned(),
        "unix:first-qmp.sock,server=on,wait=off".to_owned(),
        "-qmp".to_owned(),
        "unix:second-qmp.sock,server=on,wait=off".to_owned(),
    ]);
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::DuplicateOption { option: "-qmp" })
    );
}

fn assert_qmp_rejected(endpoint: &str, reason: &'static str) {
    let mut args = default_profile().canonical_qemu_args();
    args.extend(["-qmp".to_owned(), endpoint.to_owned()]);
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: format!("-qmp {endpoint}"),
                reason,
            }
        )
    );
}

fn assert_qmp_duplicate_rejected(endpoint: &str, key: &'static str) {
    let mut args = default_profile().canonical_qemu_args();
    args.extend(["-qmp".to_owned(), endpoint.to_owned()]);
    assert_eq!(
        validate_pre_spawn_qemu_launch_args(&args),
        Err(QemuPreSpawnLaunchValidationError::DuplicateSubOption {
            option: "-qmp",
            key,
        })
    );
}

fn option_index(args: &[String], option: &str) -> usize {
    args.iter()
        .position(|arg| arg == option)
        .unwrap_or_else(|| panic!("expected {option} option in argv"))
}

fn default_profile() -> DeterministicLaunchProfile {
    DeterministicLaunchProfile::conservative_default()
        .unwrap_or_else(|error| panic!("default deterministic launch profile failed: {error}"))
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

fn default_plugin_config() -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
}

fn default_qemu_binary() -> &'static str {
    "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
}

fn artifact(domain: &str, path: &str) -> QemuLaunchArtifact {
    QemuLaunchArtifact::new(ContentHash::from_canonical_material(domain, path), path)
}
