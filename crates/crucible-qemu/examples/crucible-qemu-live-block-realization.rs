//! Runs the live crucible-shmem block-driver realization gate.
//!
//! Boots the patched QEMU binary with a crucible-shmem virtio-blk device
//! attached through the legacy `-drive driver=crucible-shmem` interface and the
//! CPU frozen at reset, negotiates QMP, and asserts the VM reached the
//! `prelaunch` run state. Prints machine-checkable evidence the phase2 gate
//! asserts: reaching prelaunch proves the crucible-shmem block driver is
//! registered and opened rather than rejected at argv parse.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use crucible_qemu::{BlockRealizationGateConfig, run_block_realization_gate};

/// Default crucible-shmem device length: 4 MiB, a whole sector multiple.
#[cfg(target_os = "linux")]
const DEFAULT_SIZE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-block-realization: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-block-realization"));
    let qemu = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let size_bytes = match args.next() {
        Some(value) => value
            .to_string_lossy()
            .parse::<u64>()
            .map_err(|_| String::from("device size must be a base-10 byte count"))?,
        None => DEFAULT_SIZE_BYTES,
    };
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let qemu = qemu
        .into_string()
        .map_err(|_| String::from("qemu path is not valid UTF-8"))?;
    let run_directory = run_directory
        .into_string()
        .map_err(|_| String::from("run directory is not valid UTF-8"))?;

    let config = BlockRealizationGateConfig::new(qemu, run_directory, size_bytes);
    let report = run_block_realization_gate(&config).map_err(|error| error_chain(&error))?;

    println!("PASS");
    println!("gate=gate:block-realization");
    println!("block_driver=crucible-shmem");
    println!("open_interface=drive-driver-legacy");
    println!("driver_opened={}", report.driver_opened);
    println!("run_state={}", report.run_state);
    println!("orderly_child_exit={}", report.orderly_child_exit);
    Ok(())
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
    format!("usage: {program} QEMU RUN_DIRECTORY [SIZE_BYTES]")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-block-realization requires Linux");
}
