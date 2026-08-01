//! Runs the live-QEMU host-worker parallelism acceptance gate.
//!
//! Positional arguments are
//! `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]`. The gate boots two
//! production QEMU nodes for a one-worker reference and two more for a two-worker
//! dispatch, then prints measured overlap and bit-identity evidence.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_host_parallel_gate};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-host-parallel: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-host-parallel"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_HOST_PARALLEL_TIMEOUT_SECS",
            240,
        )?));
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    if let Ok(cmdline) = env::var("CRUCIBLE_HOST_PARALLEL_KERNEL_APPEND") {
        config = config.with_kernel_cmdline(cmdline);
    }

    let report = run_qemu_live_host_parallel_gate(&config).map_err(|error| error_chain(&error))?;
    println!("PASS");
    println!("gate=gate:live-host-parallel");
    println!("backend=real-qemu-node");
    println!(
        "serial_realized_parallelism={}",
        report.serial_realized_parallelism
    );
    println!(
        "parallel_realized_parallelism={}",
        report.parallel_realized_parallelism
    );
    println!(
        "serial_dispatch_wall_us={}",
        report.serial_dispatch_wall.as_micros()
    );
    println!(
        "parallel_dispatch_wall_us={}",
        report.parallel_dispatch_wall.as_micros()
    );
    println!(
        "serial_evidence_hash={}",
        report.serial_evidence_hash.to_hex()
    );
    println!(
        "parallel_evidence_hash={}",
        report.parallel_evidence_hash.to_hex()
    );
    println!("state_bit_identical={}", report.state_bit_identical);
    println!("time_bit_identical={}", report.time_bit_identical);
    println!(
        "canonical_log_bit_identical={}",
        report.canonical_log_bit_identical
    );
    println!("worker_count_in_content_hash=false");
    Ok(())
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
fn error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-host-parallel requires Linux");
}
