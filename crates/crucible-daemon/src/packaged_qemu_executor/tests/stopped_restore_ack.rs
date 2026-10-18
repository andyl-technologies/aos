//! Operation-only support from modeled immutable deployment artifact markers.
//!
//! These files model the trusted package markers, not a real plugin or native
//! completion. The actual decoder, packaged launch-path check and configuration
//! refusal are exercised before any lifecycle can publish a Restore body.

use std::error::Error;
use std::fs;

use super::*;

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_requires_supported_operation_and_exact_selected_launch() -> Result<(), Box<dyn Error>> {
    let owner = tempfile::tempdir()?;
    let root = owner.path();
    fs::create_dir_all(root.join("bin"))?;
    fs::create_dir_all(root.join("lib"))?;
    fs::create_dir_all(root.join("share/aos/crucible"))?;
    fs::create_dir_all(root.join("nix-support"))?;
    let qemu = root.join("bin/qemu-system-x86_64");
    let plugin = root.join("lib/libcrucible_qemu_plugin.so");
    fs::write(&qemu, b"modeled QEMU artifact")?;
    fs::write(&plugin, b"modeled plugin artifact")?;
    let abi_version = crucible::SHMEM_ABI_VERSION;
    fs::write(
        root.join("share/aos/crucible/qemu-build-identity.env"),
        format!(
            "qemu_sim_capability=qemu-crucible\n\
             qemu_crucible_atomic_patch_applied=true\n\
             qemu_plugins_enabled=true\n\
             qemu_build_id=qemu-test\n\
             qemu_atomic_patch_hash=sha256:modeled-patch\n\
             qemu_shmem_abi_version={abi_version}\n\
             qemu_shmem_abi=crucible-shmem-abi-v{abi_version}\n\
             qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
             qemu_shmem_header_hash=sha256:modeled-header\n"
        ),
    )?;
    let marker = root.join("nix-support/crucible-qemu-plugin-build-info");
    let baseline = format!(
        "plugin_abi=crucible-shmem-abi-v{abi_version}\n\
         qemu_build_id=qemu-test\n\
         shmem_abi_version={abi_version}\n\
         shmem_abi=crucible-shmem-abi-v{abi_version}\n\
         shmem_generated_header_hash=sha256:modeled-header\n"
    );
    let lifecycle = ProductionVmLifecycleConfig::new(
        &qemu,
        &plugin,
        root.join("kernel"),
        root.join("root-image"),
        root.join("run-state"),
    );
    let maximum_resources = HotCheckpointResourceProfile::new(1, 0, 1, 1, 1, 0)?;
    let limits = HotCheckpointLimits::new(1, maximum_resources, 1, 1)?;

    for version in [None, Some("2"), Some("1")] {
        let suffix = version.map_or_else(String::new, |version| {
            format!("stopped_restore_ack_notification_version={version}\n")
        });
        fs::write(&marker, format!("{baseline}{suffix}"))?;
        let cold = QemuLaunchArtifactIdentity::authenticate(&qemu, &plugin)?;
        assert_eq!(cold.plugin(), plugin);
        let authenticated = PackagedQemuHotForkConfig::authenticate(
            &lifecycle,
            limits,
            HotCheckpointHotnessSignals::new(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        if version != Some("1") {
            assert!(matches!(
                authenticated,
                Err(PackagedQemuHotForkConfigError::StoppedRestoreAck(_))
            ));
            continue;
        }

        let hot_fork = authenticated?;
        let selected_profile = ExecutorCompatibilityProfile::new(
            "crucible-test",
            cold.qemu_build_id(),
            std::collections::BTreeMap::from([(String::from("control"), 4)]),
            1,
            1,
        )?;
        authenticate_packaged_hot_fork_launch(&lifecycle, &hot_fork, &selected_profile)?;
        let foreign_plugin = root.join("lib/another-plugin.so");
        fs::write(&foreign_plugin, b"another modeled plugin artifact")?;
        let drifted = ProductionVmLifecycleConfig::new(
            &qemu,
            foreign_plugin,
            root.join("kernel"),
            root.join("root-image"),
            root.join("run-state"),
        );
        assert!(matches!(
            authenticate_packaged_hot_fork_launch(&drifted, &hot_fork, &selected_profile),
            Err(PackagedQemuExecutorError::HotForkLaunchPathMismatch)
        ));

        let mut wrong_receipt = hot_fork.clone();
        wrong_receipt.launch = QemuLaunchArtifactIdentity::authenticate(&qemu, drifted.plugin())?;
        assert!(matches!(
            authenticate_packaged_hot_fork_launch(&drifted, &wrong_receipt, &selected_profile),
            Err(PackagedQemuExecutorError::StoppedRestoreAck(_))
        ));
    }
    Ok(())
}
