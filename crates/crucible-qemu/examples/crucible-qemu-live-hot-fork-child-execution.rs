//! Runs a quantum in a real hot-fork child and compares it with an exact restore.
//!
//! ```text
//! crucible-qemu-live-hot-fork-child-execution QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT
//! ```
//!
//! Firmware executes bounded busy windows; the kernel argument supplies launch
//! identity material but is not booted. Invoke only with dedicated empty
//! cgroup-v2 and ext4 project-quota roots inside a disposable VM.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-hot-fork-child-execution: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    use std::time::Duration;

    use crucible_qemu::{
        QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig,
        run_qemu_live_hot_fork_child_execution_gate,
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (fixed, rest) = args.split_at(args.len().min(6));
    let [qemu, plugin, kernel, firmware, cgroup_root, run_root] = fixed else {
        return Err("expected QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT [GUEST_MIB]".into());
    };
    // The guest RAM size is the one knob the RFC's comparison varies.
    let guest_memory_mib: u32 = match rest {
        [] => 128,
        [size] => size
            .to_str()
            .ok_or("GUEST_MIB must be UTF-8")?
            .parse()
            .map_err(|error| format!("GUEST_MIB must be a positive integer: {error}"))?,
        _ => return Err("expected at most one GUEST_MIB argument".into()),
    };
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_firmware_boot()
        // The child console stage requires the connected crucible-console frontend.
        .with_console_capture()
        // The comparison reads black-box fingerprints on both sides of the fork.
        .with_fingerprint(QemuLaunchPluginSwitch::On)
        .with_vm_shape(guest_memory_mib, 1, 0)
        .with_completion_timeout(Duration::from_secs(60));
    let report = run_qemu_live_hot_fork_child_execution_gate(
        &config,
        Path::new(cgroup_root),
        Path::new(run_root),
    )?;
    println!("PASS");
    println!("gate=gate:qemu-hot-fork-child-execution");
    println!("guest_memory_mib={guest_memory_mib}");
    println!("template_generation={}", report.template_generation);
    println!("child_process_id={}", report.child_process_id);
    println!("capture_icount={}", report.capture_icount);
    println!("child_boundary_icount={}", report.child_boundary_icount);
    println!("suffix_icount={}", report.suffix_icount);
    println!(
        "child_suffix_fingerprint={}",
        report.child_suffix_fingerprint
    );
    println!(
        "restore_suffix_fingerprint={}",
        report.restore_suffix_fingerprint
    );
    println!("fork_ready_ms={}", report.fork_ready_ms);
    println!("exact_restore_ms={}", report.exact_restore_ms);
    println!("child_boundary_matches_capture=true");
    println!("child_suffix_matches_exact_restore=true");
    println!(
        "genesis_replay_suffix_fingerprint={}",
        report.genesis_replay_suffix_fingerprint
    );
    println!("genesis_replay_ms={}", report.genesis_replay_ms);
    println!("child_suffix_matches_genesis_replay=true");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crucible-qemu-live-hot-fork-child-execution requires Linux");
    ExitCode::FAILURE
}
