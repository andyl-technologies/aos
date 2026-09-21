//! Runs many hot-fork child lifecycles against one retained template.
//!
//! ```text
//! crucible-qemu-live-hot-fork-child-stress QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT LIFECYCLES [RAM_MIB]
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
            eprintln!("crucible-qemu-live-hot-fork-child-stress: {error}");
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

    use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_hot_fork_child_stress_gate};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (required, ram_mib) = match args.as_slice() {
        [
            qemu,
            plugin,
            kernel,
            firmware,
            cgroup_root,
            run_root,
            lifecycles,
        ] => (
            [
                qemu,
                plugin,
                kernel,
                firmware,
                cgroup_root,
                run_root,
                lifecycles,
            ],
            128,
        ),
        [
            qemu,
            plugin,
            kernel,
            firmware,
            cgroup_root,
            run_root,
            lifecycles,
            ram_mib,
        ] => {
            let ram_mib = ram_mib
                .to_str()
                .ok_or("RAM_MIB must be UTF-8")?
                .parse()
                .map_err(|error| format!("RAM_MIB must be a positive integer: {error}"))?;
            (
                [
                    qemu,
                    plugin,
                    kernel,
                    firmware,
                    cgroup_root,
                    run_root,
                    lifecycles,
                ],
                ram_mib,
            )
        }
        _ => {
            return Err(
                "expected QEMU PLUGIN KERNEL FIRMWARE CGROUP_ROOT RUN_ROOT LIFECYCLES [RAM_MIB]"
                    .into(),
            );
        }
    };
    let [
        qemu,
        plugin,
        kernel,
        firmware,
        cgroup_root,
        run_root,
        lifecycles,
    ] = required;
    let lifecycles: u32 = lifecycles
        .to_str()
        .ok_or("LIFECYCLES must be UTF-8")?
        .parse()
        .map_err(|error| format!("LIFECYCLES must be a positive integer: {error}"))?;
    if ram_mib == 0 {
        return Err("RAM_MIB must be positive".into());
    }
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_firmware_boot()
        // The child console stage requires the connected crucible-console frontend.
        .with_console_capture()
        .with_vm_shape(ram_mib, 1, 0)
        .with_completion_timeout(Duration::from_secs(60));
    let report = run_qemu_live_hot_fork_child_stress_gate(
        &config,
        Path::new(cgroup_root),
        Path::new(run_root),
        lifecycles,
    )?;
    println!("PASS");
    println!("gate=gate:qemu-hot-fork-child-lifecycle-stress");
    println!("template_generation={}", report.template_generation);
    println!("lifecycles={}", report.lifecycles);
    println!("guest_ram_mib={ram_mib}");
    println!(
        "last_child_files_generation={}",
        report.last_child_files_generation
    );
    println!("source_vmstate_bytes={}", report.source_vmstate_bytes);
    println!("source_allocated_bytes={}", report.source_allocated_bytes);
    println!("source_threads={}", report.source_threads);
    println!("source_descriptors={}", report.source_descriptors);
    println!("source_threads_leaked={}", report.source_threads_leaked);
    println!(
        "source_descriptors_leaked={}",
        report.source_descriptors_leaked
    );
    println!(
        "source_private_dirty_after_warmup_kib={}",
        report.source_private_dirty_after_warmup_kib
    );
    println!(
        "source_private_dirty_final_kib={}",
        report.source_private_dirty_final_kib
    );
    println!(
        "source_private_dirty_growth_kib={}",
        report.source_private_dirty_growth_kib
    );
    println!("max_fork_ms={}", report.max_fork_ms);
    println!("max_ready_ms={}", report.max_ready_ms);
    println!(
        "fork_latency_ms={}",
        joined_samples(&report.fork_latency_ms)
    );
    println!(
        "ready_latency_ms={}",
        joined_samples(&report.ready_latency_ms)
    );
    println!("max_child_rss_anon_kib={}", report.max_child_rss_anon_kib);
    println!(
        "max_child_private_dirty_kib={}",
        report.max_child_private_dirty_kib
    );
    println!(
        "max_child_private_rss_kib={}",
        report.max_child_private_rss_kib
    );
    println!(
        "max_child_allocated_bytes={}",
        report.max_child_allocated_bytes
    );
    println!("total_ms={}", report.total_ms);
    println!("run_root_entries={}", report.run_root_entries);
    let samples: Vec<String> = report
        .private_dirty_samples
        .iter()
        .map(|(lifecycles, kib)| format!("{lifecycles}:{kib}"))
        .collect();
    println!("private_dirty_samples={}", samples.join(","));
    Ok(())
}

#[cfg(target_os = "linux")]
fn joined_samples(samples: &[u64]) -> String {
    samples
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("crucible-qemu-live-hot-fork-child-stress requires Linux");
    ExitCode::FAILURE
}
