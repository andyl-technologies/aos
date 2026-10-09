//! Retains a Linux CPL3 probe on the original host driver and ownership path.

use super::*;
use std::io::Write;

#[path = "linux/runtime_trace.rs"]
mod runtime_trace;

// These are the existing production Linux-flight ceiling and completion policy.
const LINUX_POLICY: ProbePolicy = ProbePolicy {
    ceiling_ps: i64::MAX.unsigned_abs(),
    completion_timeout: Duration::from_secs(300),
    fixed_buffer: None,
    profile: "linux-cpl3-parent-buffer",
    advisory_console: true,
    runtime_trace: false,
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
    let runtime_trace =
        runtime_trace::enabled(std::env::var_os(runtime_trace::ENVIRONMENT).as_deref());
    let config = configuration(qemu, plugin, guest, root, profile, runtime_trace)?;
    let policy = ProbePolicy {
        runtime_trace,
        ..LINUX_POLICY
    };
    run_owned(qemu, cgroup, root, mode, config, policy)?;
    println!("linux_profile={profile}");
    Ok(())
}

fn configuration(
    qemu: &Path,
    plugin: &Path,
    guest: BootArtifacts<'_>,
    root: &Path,
    profile: &str,
    runtime_trace: bool,
) -> Result<QemuLiveNodeStepGateConfig, Box<dyn Error>> {
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, guest.kernel, guest.firmware, root)
        .with_initrd(guest.initrd)
        .with_vm_shape(128, 1)
        .with_console_capture()
        .with_kernel_cmdline(format!(
            "console=ttyS0 panic=-1 quiet rdinit=/init crucible_out_probe={profile}"
        ))
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_selectable_catalog_plan(catalog()?)
        .with_completion_timeout(LINUX_POLICY.completion_timeout);
    Ok(if runtime_trace {
        config.with_runtime_determinism_trace()
    } else {
        config
    })
}

pub(super) fn report_runtime_trace_after_reap(
    directory: &crucible_qemu::QemuPreparedRunDirectory,
    shutdown: Option<&QemuShutdownReport>,
) {
    runtime_trace::report_after_reap(directory, shutdown);
}

// These existing state reads do not drain events or pending requests. A failed
// read is advisory only; the caller still returns the original probe error and
// executes the original owned cleanup.
pub(super) fn report_failure(node: &mut QemuNode) {
    let mut output = std::io::stderr().lock();
    let _ = writeln!(
        output,
        "linux probe advisory state: calibration={:?}; idle={:?}; last_completed_boundary={:?}",
        node.logical_time_calibration(),
        node.idle_state(),
        node.completed_quantum_boundary()
    );
    if let Some(plan) = node.selectable_catalog_plan() {
        let continuation = plan.continuation();
        let _ = writeln!(
            output,
            "linux probe host-mirrored catalog: phase={:?}; last_registration={:?}; last_completed_request={:?}; total_completed={}; registered_count={}",
            continuation.phase(),
            continuation.last_registration_sequence(),
            continuation.last_completed_request_sequence(),
            continuation.total_completed_requests(),
            continuation.registered().len()
        );
    } else {
        let _ = writeln!(output, "linux probe host-mirrored catalog: unavailable");
    }

    match node.accepted_native_console_tail() {
        Some(bytes) => {
            let _ = writeln!(
                output,
                "linux probe untimed advisory accepted native console tail since last successful observation drain: retained_tail_bytes={}; escaped={}",
                bytes.len(),
                escaped_console_tail(&bytes)
            );
        }
        None => {
            let _ = writeln!(
                output,
                "linux probe untimed advisory console tail: unavailable (absent, busy or poisoned)"
            );
        }
    }
}

fn escaped_console_tail(bytes: &[u8]) -> String {
    bytes[bytes.len().saturating_sub(4096)..]
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
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
            false,
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
            false,
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
    fn linux_refusal_rejects_an_expired_completion_watchdog() {
        use crucible_qemu::{QemuBoundedAwaitTimeout, QemuCrashedNodeStatus};

        for timeout in [Duration::from_secs(299), LINUX_POLICY.completion_timeout] {
            let status = QemuNodeRunStatus::Crashed(QemuCrashedNodeStatus::new(
                "out-crash",
                QemuCrashCause::BoundedAwaitTimeout(QemuBoundedAwaitTimeout::new(
                    "advance completion",
                    timeout,
                )),
            ));
            assert!(require_refusal_crash_status(&status).is_err());
        }
    }

    fn setup(node: &str, tick: u64) -> ObservableEvent {
        ObservableEvent::guest_marker(
            Icount { retired: tick },
            crucible::NodeId { name: node.into() },
            crucible::MarkerId::from_name("lifecycle.setup_complete"),
        )
    }

    fn frame(node: &str, instance: &str, tick: u64) -> ObservableEvent {
        ObservableEvent::guest_semantic_marker(
            Icount { retired: tick },
            crucible::NodeId { name: node.into() },
            "out.frame",
            instance,
            Vec::new(),
        )
    }

    fn console() -> ObservableEvent {
        ObservableEvent::console_output(
            VirtualTime { ticks: 17 },
            crucible::NodeId { name: NODE.into() },
            b"console".to_vec(),
        )
    }

    fn unrelated() -> ObservableEvent {
        ObservableEvent::node_state(
            VirtualTime { ticks: 17 },
            crucible::NodeId { name: NODE.into() },
            crucible::NodeLifecycle::Started,
        )
    }

    #[test]
    fn console_filter_preserves_the_original_ordered_boundary_frames() -> Result<(), Box<dyn Error>>
    {
        let first = probe_events(
            vec![
                console(),
                setup(NODE, 10),
                console(),
                frame(NODE, "first", 20),
                console(),
            ],
            LINUX_POLICY,
        );
        assert_eq!(first, vec![setup(NODE, 10), frame(NODE, "first", 20)]);
        require_first_events(&first)?;

        let second = probe_events(
            vec![console(), frame(NODE, "second", 30), console()],
            LINUX_POLICY,
        );
        assert_eq!(second, vec![frame(NODE, "second", 30)]);
        require_second_events(&second)?;
        Ok(())
    }

    #[test]
    fn console_filter_keeps_missing_duplicate_and_unrelated_events_as_failures() {
        for events in [
            vec![console(), frame(NODE, "first", 20)],
            vec![console(), setup(NODE, 10)],
            vec![
                setup(NODE, 10),
                setup(NODE, 10),
                frame(NODE, "first", 20),
                console(),
            ],
            vec![
                setup(NODE, 10),
                frame(NODE, "first", 20),
                frame(NODE, "first", 20),
                console(),
            ],
            vec![
                setup(NODE, 10),
                unrelated(),
                frame(NODE, "first", 20),
                console(),
            ],
            vec![frame(NODE, "first", 20), setup(NODE, 10), console()],
            vec![setup("other", 10), frame(NODE, "first", 20), console()],
            vec![setup(NODE, 10), frame("other", "first", 20), console()],
            vec![setup(NODE, 20), frame(NODE, "first", 20), console()],
        ] {
            assert!(require_first_events(&probe_events(events, LINUX_POLICY)).is_err());
        }

        for events in [
            vec![console()],
            vec![
                frame(NODE, "second", 30),
                frame(NODE, "second", 30),
                console(),
            ],
            vec![frame(NODE, "second", 30), unrelated(), console()],
            vec![frame(NODE, "first", 30), console()],
            vec![frame("other", "second", 30), console()],
        ] {
            assert!(require_second_events(&probe_events(events, LINUX_POLICY)).is_err());
        }
    }

    #[test]
    fn rom_keeps_console_output_in_its_original_cardinality_check() {
        let first = vec![setup(NODE, 10), frame(NODE, "first", 20), console()];
        assert_eq!(probe_events(first.clone(), ROM_POLICY), first);
        assert!(require_first_events(&probe_events(first, ROM_POLICY)).is_err());
        let second = vec![frame(NODE, "second", 30), console()];
        assert_eq!(probe_events(second.clone(), ROM_POLICY), second);
        assert!(require_second_events(&probe_events(second, ROM_POLICY)).is_err());
    }

    #[test]
    fn advisory_console_tail_preserves_heading_before_a_long_stack() {
        let heading = b"Linux OUT probe: original SDK error\r\nKernel panic - not syncing: original kernel error\r\n";
        let stack = b"[    0.461032] entry_SYSCALL_64_after_hwframe+0x77/0x7f\r\n".repeat(40);
        let mut bytes = vec![b'x'; 4096];
        bytes.extend_from_slice(heading);
        bytes.extend_from_slice(&stack);

        let escaped = escaped_console_tail(&bytes);

        assert!(stack.len() > 1024);
        assert!(escaped.contains("Linux OUT probe: original SDK error"));
        assert!(escaped.contains("Kernel panic - not syncing: original kernel error"));
        assert!(escaped.contains("entry_SYSCALL_64_after_hwframe"));
        assert!(!escaped.contains('\n'));
        assert!(escaped.len() <= 16384);
    }

    #[test]
    fn advisory_console_tail_escapes_binary_bytes_without_exceeding_sixteen_kib() {
        assert_eq!(
            escaped_console_tail(b"a\n\r\t\"\\\xff"),
            "a\\n\\r\\t\\\"\\\\\\xff"
        );
        let mut bytes = b"omitted prefix".to_vec();
        bytes.extend([0xff; 4096]);

        let escaped = escaped_console_tail(&bytes);
        assert_eq!(escaped, "\\xff".repeat(4096));
        assert_eq!(escaped.len(), 16384);
        assert!(!escaped.contains('\n'));
        assert!(escaped_console_tail(&[]).is_empty());
    }
}
