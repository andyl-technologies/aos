//! Retains a Linux CPL3 probe on the original host driver and ownership path.

use super::*;

// These are the existing production Linux-flight ceiling and completion policy.
const LINUX_POLICY: ProbePolicy = ProbePolicy {
    ceiling_ps: i64::MAX.unsigned_abs(),
    completion_timeout: Duration::from_secs(300),
    fixed_buffer: None,
    profile: "linux-cpl3-parent-buffer",
};

/// Keeps the three distinct immutable Linux boot artifacts together.
#[derive(Clone, Copy)]
pub(super) struct BootArtifacts<'a> {
    pub(super) kernel: &'a Path,
    pub(super) initrd: &'a Path,
    pub(super) firmware: &'a Path,
}

pub(super) fn flight(
    qemu: &Path,
    plugin: &Path,
    guest: BootArtifacts<'_>,
    cgroup: &Path,
    root: &Path,
    profile: &Path,
) -> Result<(), Box<dyn Error>> {
    let profile = match profile.to_str() {
        Some("no-child") => "no-child",
        Some("exec-child") => "exec-child",
        Some("late-register") => "late-register",
        _ => return Err("expected no-child, exec-child or late-register".into()),
    };
    let mode = if profile == "late-register" {
        Mode::LateRegister
    } else {
        Mode::Normal
    };
    let config = configuration(qemu, plugin, guest, root, profile)?;
    run_owned(qemu, cgroup, root, mode, config, LINUX_POLICY)?;
    println!("linux_profile={profile}");
    Ok(())
}

fn configuration(
    qemu: &Path,
    plugin: &Path,
    guest: BootArtifacts<'_>,
    root: &Path,
    profile: &str,
) -> Result<QemuLiveNodeStepGateConfig, Box<dyn Error>> {
    Ok(
        QemuLiveNodeStepGateConfig::new(qemu, plugin, guest.kernel, guest.firmware, root)
            .with_initrd(guest.initrd)
            .with_vm_shape(128, 1)
            .with_kernel_cmdline(format!(
                "console=ttyS0 panic=-1 quiet rdinit=/init crucible_out_probe={profile}"
            ))
            .with_whitebox(QemuLaunchPluginSwitch::On)
            .with_selectable_catalog_plan(catalog()?)
            .with_completion_timeout(LINUX_POLICY.completion_timeout),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_configuration_retains_the_distinct_firmware_artifact() -> Result<(), Box<dyn Error>> {
        let guest = BootArtifacts {
            kernel: Path::new("/aos/kernel/bzImage"),
            initrd: Path::new("/aos/guest/initrd.img"),
            firmware: Path::new("/aos/qemu/share/qemu/bios-256k.bin"),
        };
        let config = configuration(
            Path::new("/aos/qemu/bin/qemu-system-x86_64"),
            Path::new("/aos/plugin/lib/plugin.so"),
            guest,
            Path::new("/run/crucible"),
            "exec-child",
        )?;
        let wrong_firmware = configuration(
            Path::new("/aos/qemu/bin/qemu-system-x86_64"),
            Path::new("/aos/plugin/lib/plugin.so"),
            BootArtifacts {
                firmware: guest.kernel,
                ..guest
            },
            Path::new("/run/crucible"),
            "exec-child",
        )?;

        assert_ne!(
            config, wrong_firmware,
            "the BIOS input must affect the actual launch configuration"
        );
        Ok(())
    }

    #[test]
    fn linux_buffer_identity_stays_bound_to_the_first_original_request() {
        assert!(!buffer_matches(None, 0));
        assert!(buffer_matches(None, 0x7fff_1000));
        assert!(buffer_matches(Some(0x7fff_1000), 0x7fff_1000));
        assert!(!buffer_matches(Some(0x7fff_1000), 0x7fff_2000));
        assert!(!buffer_matches(Some(BUFFER), 0x7fff_1000));
    }

    #[test]
    fn linux_refusal_retains_the_original_remaining_budget_bound() {
        use crucible_qemu::{QemuBoundedAwaitTimeout, QemuCrashedNodeStatus};

        let status = |timeout| {
            QemuNodeRunStatus::Crashed(QemuCrashedNodeStatus::new(
                "out-crash",
                QemuCrashCause::BoundedAwaitTimeout(QemuBoundedAwaitTimeout::new(
                    "advance completion",
                    timeout,
                )),
            ))
        };
        assert!(
            require_refusal_crash_status_with_budget(
                &status(Duration::from_secs(299)),
                LINUX_POLICY.completion_timeout,
            )
            .is_ok()
        );
        assert!(
            require_refusal_crash_status_with_budget(
                &status(Duration::from_secs(301)),
                LINUX_POLICY.completion_timeout,
            )
            .is_err()
        );
        assert!(require_refusal_crash_status(&status(Duration::from_secs(299))).is_err());
    }
}
