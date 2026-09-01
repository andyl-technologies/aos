//! Runs the certifying live 9p-I/O gate over `SLOT_9P_IO`.
//!
//! Boots the diskless-firmware guest with a `crucible-shmem` virtio-9p device
//! and a mount-workload initrd, drives a raw shared-memory hot path toward a busy
//! ceiling while a host servicer drains `SLOT_9P_IO`, and prints what the
//! servicing observed: how many 9p requests were serviced, the device completion
//! horizon for the first request, and the guest slot's published device-I/O
//! state. The guest must complete that request and reach the scheduler ceiling.
//! The run repeats under bounded scheduler preemption with a delayed due response, and the two
//! runs' icount-domain observations must match.
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY INITRD`. The
//! initrd is REQUIRED: a virtio-9p filesystem is untouched until userspace mounts
//! it, so the guest must actively `mount -t 9p` to exercise the data path.
//! Tuning is read from the environment:
//!
//! ```text
//! CRUCIBLE_9P_IO_BUSY_CEILING    icount the single advance drives toward
//! CRUCIBLE_9P_IO_TIMEOUT_SECS    per-advance host wait bound (seconds)
//! CRUCIBLE_9P_IO_SECOND_RUN_SCHEDULER_PREEMPTION "0" disables second-run bounded scheduler preemption
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
use crucible_qemu::{NinepIoAdvanceOutcome, QemuLive9pIoGateConfig, run_qemu_live_9p_io_gate};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-ninep-io: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-ninep-io"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = required_arg(&mut args, &program)?;
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let config = QemuLive9pIoGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
        .with_initrd(initrd)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_9P_IO_TIMEOUT_SECS",
            120,
        )?))
        .with_second_run_scheduler_preemption(env_flag(
            "CRUCIBLE_9P_IO_SECOND_RUN_SCHEDULER_PREEMPTION",
            true,
        )?);
    let config = match env_opt_u64("CRUCIBLE_9P_IO_BUSY_CEILING")? {
        Some(ceiling) => config.with_busy_ceiling_icount(ceiling),
        None => config,
    };

    let report = run_qemu_live_9p_io_gate(&config).map_err(|error| error_chain(&error))?;
    let diagnostics = &report.diagnostics;

    println!("PASS");
    println!("gate=gate:live-9p-io");
    println!("certification=9p-forward-and-completion-under-sim");
    println!("plugin_loaded=rust-control-cdylib");
    println!("node_kind=raw-hot-path-drive");
    println!("ninep_backend=crucible-shmem-host-servicer");
    println!("ninep_ring=SLOT_9P_IO");
    // Control: the same guest issues a real 9p op under TCG (sim absent).
    println!("tcg_control_issued_9p={}", report.tcg_control_issued_9p);
    println!("sim_leg_forwarded=true");
    println!("frames_processed={}", diagnostics.frames_processed);
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
        NinepIoAdvanceOutcome::ReachedCeiling { icount } => {
            println!("advance_outcome=closed-ceiling");
            println!("ceiling_closure=retired-to-ceiling");
            println!("guest_progressed_past_ninep_io=true");
            println!("advance_icount={icount}");
        }
        NinepIoAdvanceOutcome::QuiescentThroughCeiling {
            icount,
            idle_wake_icount,
        } => {
            println!("advance_outcome=closed-ceiling");
            println!("ceiling_closure=idle-wake-beyond-ceiling");
            println!("guest_progressed_past_ninep_io=true");
            println!("advance_icount={icount}");
            println!("advance_idle_wake_icount={idle_wake_icount}");
        }
        NinepIoAdvanceOutcome::PausedBelowCeiling { icount } => {
            println!("advance_outcome=paused-below-ceiling");
            println!("guest_progressed_past_ninep_io=false");
            println!("advance_icount={icount}");
        }
        NinepIoAdvanceOutcome::Failed { detail } => {
            println!("advance_outcome=failed");
            println!("guest_progressed_past_ninep_io=false");
            println!("advance_failure={detail}");
        }
    }
    println!("orderly_child_exit={}", report.orderly_child_exit);
    println!(
        "deterministic_under_scheduler_preemption={}",
        report.deterministic_under_scheduler_preemption
    );
    println!(
        "scheduler_preemption_applied={}",
        report.scheduler_preemption_applied
    );
    println!(
        "host_adversary={}",
        if report.scheduler_preemption_applied {
            "bounded-scheduler-preemption"
        } else {
            "none"
        }
    );
    println!(
        "delayed_response_applied={}",
        report.delayed_response_applied
    );
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
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY INITRD")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-ninep-io requires Linux");
}
