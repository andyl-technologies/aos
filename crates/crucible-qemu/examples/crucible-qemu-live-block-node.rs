//! Runs the live [`QemuNode`] block-I/O bring-up gate (CP3 / T-PLUG-12).
//!
//! Boots the diskless-firmware guest on a real `QemuNode` with a crucible-shmem
//! virtio-blk device attached, weaves a host block servicer into priming and
//! advance, and classifies whether the guest stalled on the device horizon
//! (pre-0039 baseline) or progressed past the serviced block I/O (post-0039).
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]`.
//! Tuning is read from the environment:
//!
//! ```text
//! CRUCIBLE_BLOCK_NODE_BUSY_CEILING   busy-window ceiling (icount)
//! CRUCIBLE_BLOCK_NODE_TIMEOUT_SECS   per-phase host wait bound (seconds)
//! CRUCIBLE_BLOCK_NODE_DEVICE_SIZE    block-device size (bytes)
//! ```

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crucible_qemu::{BlockNodeOutcome, QemuLiveBlockNodeGateConfig, run_qemu_live_block_node_gate};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-block-node: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-block-node"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut config =
        QemuLiveBlockNodeGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
            .with_busy_ceiling_icount(env_u64("CRUCIBLE_BLOCK_NODE_BUSY_CEILING", 12_000_000)?)
            .with_completion_timeout(Duration::from_secs(env_u64(
                "CRUCIBLE_BLOCK_NODE_TIMEOUT_SECS",
                60,
            )?));
    if let Some(size) = env_opt_u64("CRUCIBLE_BLOCK_NODE_DEVICE_SIZE")? {
        config = config.with_device_size_bytes(size);
    }
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }

    let report = run_qemu_live_block_node_gate(&config).map_err(|error| error_chain(&error))?;
    let diag = report.diagnostics();

    println!("PASS");
    println!("gate=gate:live-block-node");
    println!("plugin_loaded=rust-control-cdylib");
    println!("node_kind=live-qemu-node");
    println!("block_backend=crucible-shmem-host-servicer");
    let outcome = match report.outcome() {
        BlockNodeOutcome::DeviceHorizonStall => "device-horizon-stall",
        BlockNodeOutcome::ProgressedPastBlockIo => "progressed-past-block-io",
    };
    println!("outcome={outcome}");
    println!(
        "guest_progressed_past_block_io={}",
        report.guest_progressed_past_block_io()
    );
    println!("frames_processed={}", diag.frames_processed);
    println!("frames_delivered={}", diag.frames_delivered);
    println!("reached_icount={}", report.reached_icount());
    match diag.first_completion_horizon {
        Some(horizon) => println!("first_completion_horizon={horizon}"),
        None => println!("first_completion_horizon=none"),
    }
    println!("last_device_io_active={}", diag.last_device_io_active);
    Ok(())
}

#[cfg(target_os = "linux")]
fn env_u64(key: &str, fallback: u64) -> Result<u64, String> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| format!("environment variable {key} is not a u64: {error}")),
        Err(env::VarError::NotPresent) => Ok(fallback),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} is not valid UTF-8"))
        }
    }
}

#[cfg(target_os = "linux")]
fn env_opt_u64(key: &str) -> Result<Option<u64>, String> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|error| format!("environment variable {key} is not a u64: {error}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} is not valid UTF-8"))
        }
    }
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

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-block-node requires Linux");
}
