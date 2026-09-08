//! Forks several independent retained templates into children alive together.
//!
//! ```text
//! crucible-qemu-live-hot-fork-child-world QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT NODE_COUNT
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
            eprintln!("crucible-qemu-live-hot-fork-child-world: {error}");
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

    use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_hot_fork_child_world_gate};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [
        qemu,
        plugin,
        kernel,
        firmware,
        cgroup_root,
        run_root,
        node_count,
    ] = args.as_slice()
    else {
        return Err("expected QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT NODE_COUNT".into());
    };
    let node_count: u32 = node_count
        .to_str()
        .ok_or("NODE_COUNT must be UTF-8")?
        .parse()
        .map_err(|error| format!("NODE_COUNT must be a positive integer: {error}"))?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_firmware_boot()
        // The child console stage requires the connected crucible-console frontend.
        .with_console_capture()
        .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
        .with_vm_shape(128, 1, 0)
        .with_completion_timeout(Duration::from_secs(60));
    let report = run_qemu_live_hot_fork_child_world_gate(
        &config,
        Path::new(cgroup_root),
        Path::new(run_root),
        node_count,
    )?;
    println!("PASS");
    println!("gate=gate:qemu-hot-fork-child-world");
    println!("node_count={}", report.node_count);
    println!("children_alive_together={}", report.children_alive_together);
    for (index, node) in report.nodes.iter().enumerate() {
        println!("node{index}_child_process_id={}", node.child_process_id);
        println!("node{index}_capture_icount={}", node.capture_icount);
        println!("node{index}_suffix_icount={}", node.suffix_icount);
        println!("node{index}_fork_ready_ms={}", node.fork_ready_ms);
        println!("node{index}_exact_restore_ms={}", node.exact_restore_ms);
        println!("node{index}_genesis_replay_ms={}", node.genesis_replay_ms);
        println!(
            "node{index}_child_suffix_fingerprint={}",
            node.child_suffix_fingerprint
        );
    }
    println!("every_child_matches_exact_restore=true");
    println!("every_child_matches_genesis_replay=true");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crucible-qemu-live-hot-fork-child-world requires Linux");
    ExitCode::FAILURE
}
