//! Runs the certifying live block-I/O gate over `SLOT_BLK_IO`.
//!
//! Boots the diskless-firmware guest with a `crucible-shmem` virtio-blk device,
//! stands up a live node whose host-I/O runtime services `SLOT_BLK_IO`, advances
//! the node once toward a busy ceiling, and prints what the servicing observed:
//! how many block requests were serviced, the device completion horizon for the
//! first request, and the guest slot's published device-I/O state. The guest must
//! advance through that completion and reach its scheduler ceiling. The run
//! repeats under host load and the two runs' block observations must match.
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]`.
//! Tuning is read from the environment:
//!
//! ```text
//! CRUCIBLE_BLOCK_IO_DEVICE_SIZE     crucible-shmem device length in bytes
//! CRUCIBLE_BLOCK_IO_BUSY_CEILING    icount the single advance drives toward
//! CRUCIBLE_BLOCK_IO_TIMEOUT_SECS    per-advance host wait bound (seconds)
//! CRUCIBLE_BLOCK_IO_SECOND_RUN_LOAD "0" disables second-run host load
//! CRUCIBLE_BLOCK_IO_RESET_PROBE     "1" runs the live reset/errno/IRQ gate
//! GUEST_KERNEL_APPEND                explicit guest kernel command line
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
use crucible_qemu::{
    BlockIoAdvanceOutcome, QemuLiveBlockIoGateConfig, run_qemu_live_block_io_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-block-io: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-block-io"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut config = QemuLiveBlockIoGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_BLOCK_IO_TIMEOUT_SECS",
            120,
        )?))
        .with_second_run_host_load(env_flag("CRUCIBLE_BLOCK_IO_SECOND_RUN_LOAD", true)?)
        .with_transport_reset_probe(env_flag("CRUCIBLE_BLOCK_IO_RESET_PROBE", false)?);
    if let Some(size) = env_opt_u64("CRUCIBLE_BLOCK_IO_DEVICE_SIZE")? {
        config = config.with_device_size_bytes(size);
    }
    if let Some(ceiling) = env_opt_u64("CRUCIBLE_BLOCK_IO_BUSY_CEILING")? {
        config = config.with_busy_ceiling_icount(ceiling);
    }
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    if let Some(kernel_cmdline) = env::var_os("GUEST_KERNEL_APPEND") {
        config = config.with_kernel_cmdline(kernel_cmdline.to_string_lossy());
    }

    let report = run_qemu_live_block_io_gate(&config).map_err(|error| error_chain(&error))?;
    let diagnostics = &report.diagnostics;

    println!("PASS");
    println!("gate=gate:live-block-io");
    println!("plugin_loaded=rust-control-cdylib");
    println!("node_kind=live-qemu-node");
    println!("block_backend=crucible-shmem-host-servicer");
    println!("block_ring=SLOT_BLK_IO");
    // Diagnostic observations. frames_processed>0 proves real guest block I/O
    // flowed over SLOT_BLK_IO to the host servicer.
    println!("frames_processed={}", diagnostics.frames_processed);
    println!(
        "write_frames_processed={}",
        diagnostics.write_frames_processed
    );
    println!("frames_delivered={}", diagnostics.frames_delivered);
    println!("service_calls={}", diagnostics.service_calls);
    println!(
        "first_request_icount={}",
        option_u64(diagnostics.first_request_icount)
    );
    println!(
        "first_completion_horizon={}",
        option_u64(diagnostics.first_completion_horizon)
    );
    println!("last_current_icount={}", diagnostics.last_current_icount);
    println!("max_current_icount={}", diagnostics.max_current_icount);
    println!(
        "last_device_io_active={}",
        diagnostics.last_device_io_active
    );
    println!(
        "last_idle_wake_icount={}",
        diagnostics.last_idle_wake_icount
    );
    match &report.advance {
        BlockIoAdvanceOutcome::ReachedCeiling { icount } => {
            println!("advance_outcome=reached-ceiling");
            println!("advance_icount={icount}");
            println!("guest_progressed_past_block_io=true");
        }
        BlockIoAdvanceOutcome::PausedBelowCeiling { icount } => {
            let write_completed =
                diagnostics.write_frames_processed > 0 && !diagnostics.last_device_io_active;
            println!(
                "advance_outcome={}",
                if write_completed {
                    "quiesced-after-write"
                } else {
                    "paused-below-ceiling"
                }
            );
            println!("advance_icount={icount}");
            println!("guest_progressed_past_block_io={write_completed}");
        }
        BlockIoAdvanceOutcome::Failed { detail } => {
            println!("advance_outcome=failed");
            println!("advance_failure={detail}");
            println!("guest_progressed_past_block_io=false");
        }
    }
    println!("orderly_child_exit={}", report.orderly_child_exit);
    println!(
        "deterministic_under_host_load={}",
        report.deterministic_under_host_load
    );
    println!("host_load_applied={}", report.host_load_applied);
    println!(
        "delayed_response_applied={}",
        report.delayed_response_applied
    );
    println!("host_wins_race_proven={}", report.host_wins_race_proven);
    println!("guest_wins_race_proven={}", report.guest_wins_race_proven);
    println!(
        "completion_pinned_before_dispatch={}",
        report.completion_pinned_before_dispatch
    );
    println!(
        "canonical_logs_identical={}",
        report.canonical_logs_identical
    );
    if let Some(errno) = report.transport_reset_guest_errno {
        println!("transport_reset_guest_errno={errno}");
    }
    if let Some(delta) = report.transport_reset_config_interrupt_delta {
        println!("transport_reset_config_interrupt_delta={delta}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn option_u64(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("none"), |value| value.to_string())
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
fn env_flag(key: &str, fallback: bool) -> Result<bool, String> {
    match env::var(key) {
        Ok(value) => match value.trim() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(format!(
                "environment variable {key} is not a boolean: {other}"
            )),
        },
        Err(env::VarError::NotPresent) => Ok(fallback),
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
    eprintln!("crucible-qemu-live-block-io requires Linux");
}
