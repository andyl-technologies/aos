//! Retains a Linux CPL3 probe on the original host driver and ownership path.

use super::*;

// These are the existing production Linux-flight ceiling and completion policy.
const LINUX_POLICY: ProbePolicy = ProbePolicy {
    ceiling_ps: i64::MAX.unsigned_abs(),
    completion_timeout: Duration::from_secs(300),
    fixed_buffer: None,
    profile: "linux-cpl3-parent-buffer",
};

pub(super) fn flight(
    qemu: &Path,
    plugin: &Path,
    kernel: &Path,
    initrd: &Path,
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
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, kernel, root)
        .with_initrd(initrd)
        .with_vm_shape(128, 1)
        .with_kernel_cmdline(format!(
            "console=ttyS0 panic=-1 quiet rdinit=/init crucible_out_probe={profile}"
        ))
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_selectable_catalog_plan(catalog()?)
        .with_completion_timeout(LINUX_POLICY.completion_timeout);
    run_owned(qemu, cgroup, root, mode, config, LINUX_POLICY)?;
    println!("linux_profile={profile}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
