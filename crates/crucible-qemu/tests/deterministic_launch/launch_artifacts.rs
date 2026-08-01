//! Content-addressed launch-artifact integration cases.

use super::*;
use crucible_qemu::QemuRootImageFormat;

#[test]
fn raw_root_image_format_is_pinned_in_identity_and_backing_driver() {
    let command = default_profile()
        .qemu_launch_command(
            default_vm_config().with_root_image_format(QemuRootImageFormat::Raw),
            default_qemu_binary(),
            default_plugin_config(),
        )
        .unwrap_or_else(|error| panic!("raw root-image launch should build: {error}"));

    assert!(
        command
            .args()
            .iter()
            .any(|arg| arg.contains("backing.driver=raw"))
    );
    assert!(
        command
            .vm_launch_hash_material()
            .contains("root_image_format=raw")
    );
}

#[test]
fn launch_profile_binds_fw_cfg_file_to_guest_entropy_seed() {
    let profile = default_profile();
    let seed_file = profile.guest_entropy_seed_file();

    assert_eq!(seed_file.file_name(), "crucible-guest-entropy-seed.bin");
    assert_eq!(seed_file.bytes(), profile.guest_entropy_seed().bytes());
    assert!(profile.canonical_qemu_args().windows(2).any(|window| {
        window[0] == "-fw_cfg"
            && window[1] == format!("name=opt/crucible/seed,file={}", seed_file.file_name())
    }));

    let mut dir = std::env::temp_dir();
    dir.push(format!("crucible-qemu-seed-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!("failed to create temporary seed-file directory {dir:?}: {error}");
    });

    let path = seed_file.write_to_dir(&dir).unwrap_or_else(|error| {
        panic!("failed to write deterministic seed file into {dir:?}: {error}");
    });
    let written = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read deterministic seed file {path:?}: {error}");
    });
    assert_eq!(written.as_slice(), seed_file.bytes());

    std::fs::remove_dir_all(&dir).unwrap_or_else(|error| {
        panic!("failed to remove temporary seed-file directory {dir:?}: {error}");
    });
}

#[test]
fn launch_material_feeds_scenario_identity() {
    let profile = default_profile();
    let shifted = deterministic(
        LaunchProfileCandidate::default().with_icount_shift(IcountShiftSetting::Fixed(1)),
    );

    let base_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &profile.scenario_hash_material(),
    );
    let repeated_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &profile.scenario_hash_material(),
    );
    let shifted_scenario = ScenarioDef::from_canonical_material(
        "crucible.scenario.v1.qemu-launch",
        &shifted.scenario_hash_material(),
    );

    assert_eq!(base_scenario, repeated_scenario);
    assert_ne!(base_scenario.id(), shifted_scenario.id());
}
