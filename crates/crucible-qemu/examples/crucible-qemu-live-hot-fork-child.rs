//! Forks one real retained template into a child with private VMState.
//!
//! ```text
//! crucible-qemu-live-hot-fork-child QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT
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
            eprintln!("crucible-qemu-live-hot-fork-child: {error}");
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

    use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_hot_fork_child_gate};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [qemu, plugin, kernel, firmware, cgroup_root, run_root] = args.as_slice() else {
        return Err("expected QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT".into());
    };
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_firmware_boot()
        // The child console stage requires the connected crucible-console frontend.
        .with_console_capture()
        .with_vm_shape(128, 1, 0)
        .with_completion_timeout(Duration::from_secs(60));
    let report =
        run_qemu_live_hot_fork_child_gate(&config, Path::new(cgroup_root), Path::new(run_root))?;
    println!("PASS");
    println!("gate=gate:qemu-hot-fork-child-private-vmstate");
    println!("template_generation={}", report.template_generation);
    println!("child_files_generation={}", report.child_files_generation);
    println!("child_forked=true");
    println!("child_in_target_cgroup=true");
    println!("child_holds_private_vmstate_inode=true");
    println!("child_released_source_vmstate_inode=true");
    println!("source_vmstate_bytes={}", report.source_vmstate_bytes);
    println!("private_vmstate_bytes={}", report.private_vmstate_bytes);
    println!(
        "child_saved_vmstate_bytes={}",
        report.child_saved_vmstate_bytes
    );
    println!("source_vmstate_unchanged=true");
    println!("children_forked={}", report.children_forked);
    println!("source_threads={}", report.source_threads);
    println!("source_descriptors={}", report.source_descriptors);
    println!("source_threads_leaked={}", report.source_threads_leaked);
    println!(
        "source_descriptors_leaked={}",
        report.source_descriptors_leaked
    );
    println!(
        "source_private_dirty_growth_kib={}",
        report.source_private_dirty_growth_kib
    );
    println!("max_fork_ms={}", report.max_fork_ms);
    println!("max_ready_ms={}", report.max_ready_ms);
    println!("child_threads={}", report.child_threads);
    println!("child_descriptors={}", report.child_descriptors);
    println!("child_private_dirty_kib={}", report.child_private_dirty_kib);
    println!("whole_world_child_handoff=false");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crucible-qemu-live-hot-fork-child requires Linux");
    ExitCode::FAILURE
}
