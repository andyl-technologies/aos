//! Runs the live guest-clock and accelerator hardware workload.
//!
//! This gate launches the production patched QEMU process, Rust control plugin,
//! scheduler-facing [`crucible_qemu::QemuNode`], shared-memory host runtime, and
//! `virtio-crucible-accelerator` servicer. The guest itself enumerates the real
//! PCI function and submits the closed GPU, TPU, and FPGA job schemas through a
//! modern split virtqueue. Console bytes are collected only through Crucible's
//! normal observable-event path.
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY`.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use crucible::{ObservableEventPayload, SimulationBackend, VirtualTime};
#[cfg(target_os = "linux")]
use crucible_qemu::{QemuLiveNodeStepGateConfig, launch_qemu_live_node};

#[cfg(target_os = "linux")]
// Linux reaches its initramfs workload near 3.35 billion retired instructions
// under the deterministic sim accelerator. One wide, finite authorization lets
// QEMU advance directly through guest timer deadlines; scheduler boundaries are
// reserved for actual fault and device events rather than host polling slices.
const MAX_STEPS: u64 = 1;
#[cfg(target_os = "linux")]
const STEP_ICOUNT: u64 = 5_120_000_000;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-fault-hardware: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let program = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("crucible-qemu-live-fault-hardware"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let initrd = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, &run_directory)
        .with_initrd(initrd)
        .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet")
        .with_vm_shape(128, 1, 0)
        .with_accelerator()
        .with_console_capture()
        .with_second_run_host_load(false);
    let mut node = launch_qemu_live_node(
        &config,
        &run_directory,
        "fault-hardware-node",
        "fault-hardware-router",
        "fault-hardware-crash-detector",
    )
    .map_err(|error| error_chain(&error))?;

    let mut console = Vec::new();
    collect_console(&mut node, &mut console)?;
    let initial_icount = node
        .current_icount()
        .map_err(|error| format!("read live hardware guest boundary: {error}"))?
        .retired;
    for step in 1..=MAX_STEPS {
        if contains(&console, b"CRUCIBLE_FAULT_HARDWARE_GUEST=PASS\n") {
            break;
        }
        let advance = SimulationBackend::step_to(
            &mut node,
            VirtualTime {
                ticks: initial_icount
                    .checked_add(
                        step.checked_mul(STEP_ICOUNT)
                            .ok_or_else(|| String::from("guest step span overflowed"))?,
                    )
                    .ok_or_else(|| String::from("guest step coordinate overflowed"))?,
            },
        );
        if let Err(error) = advance {
            let _ = collect_console(&mut node, &mut console);
            return Err(format!(
                "advance live hardware guest: {error}; console follows:\n{}",
                String::from_utf8_lossy(&console)
            ));
        }
        collect_console(&mut node, &mut console)?;
    }

    let output = String::from_utf8(console)
        .map_err(|error| format!("guest console was not UTF-8: {error}"))?;
    for required in [
        "CRUCIBLE_FAULT_HARDWARE_GUEST=READY",
        "CRUCIBLE_CLOCK_BEFORE counter=",
        "CRUCIBLE_ACCELERATOR_GPU status=0 length=8 values=4,6",
        "CRUCIBLE_ACCELERATOR_TPU status=0 length=4 value=23",
        "CRUCIBLE_ACCELERATOR_FPGA status=0 length=3 values=255,254,0",
        "CRUCIBLE_CLOCK_AFTER counter=",
        "CRUCIBLE_FAULT_HARDWARE_GUEST=PASS",
    ] {
        if !output.contains(required) {
            return Err(format!(
                "live hardware guest omitted `{required}`; console follows:\n{output}"
            ));
        }
    }

    let shutdown = node
        .shutdown_child()
        .map_err(|error| format!("shut down live hardware guest: {error}"))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(String::from("live hardware QEMU child was not reaped"));
    }

    println!("PASS");
    println!("gate=gate:live-fault-hardware");
    println!("guest_clock_reads=architecture-counter,posix-monotonic,posix-realtime");
    println!("accelerator_transport=real-modern-virtio-pci");
    println!("accelerator_jobs=gpu-vector-add,tpu-matrix-multiply,fpga-lookup-table");
    println!("host_adapter=qemu-live-accelerator-servicer");
    println!("orderly_child_exit=true");
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_console(node: &mut crucible_qemu::QemuNode, output: &mut Vec<u8>) -> Result<(), String> {
    let events = SimulationBackend::drain_observable_events(node)
        .map_err(|error| format!("drain live guest observations: {error}"))?;
    for event in events {
        if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
            output.extend_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY")
}

#[cfg(target_os = "linux")]
fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        message.push_str(": ");
        message.push_str(&current.to_string());
        source = current.source();
    }
    message
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-fault-hardware requires Linux");
}
