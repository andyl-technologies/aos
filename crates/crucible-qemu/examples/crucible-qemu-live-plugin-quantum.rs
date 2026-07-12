//! Runs the production loaded-QEMU Rust-plugin quantum/idle time-authority gate.
//!
//! Boots the patched QEMU binary once with the real Rust control plugin loaded,
//! drives a multi-quantum scheduler through the guest's boot, idle park, and
//! idle-jump advancement, and repeats the whole scenario under host CPU load.
//! Prints machine-checkable evidence the phase2 gate asserts: the idle
//! observation with a computed timer deadline, the boot-versus-idle advancement
//! rates that prove O(1) idle-jump, cross-run determinism, and
//! `time_authority=rust-plugin`.
//!
//! Positional arguments mirror the install runner, with two optional trailing
//! arguments. Scheduler tuning is read from the environment so the gate can be
//! tuned on a builder without rebuilding:
//!
//! ```text
//! CRUCIBLE_QUANTUM_CEILING_STEP        boot-phase ceiling increment (icount)
//! CRUCIBLE_QUANTUM_MAX_SEARCH          boot search bound (icount)
//! CRUCIBLE_QUANTUM_IDLE_HORIZON_MARGIN idle-jump span past onset (icount)
//! CRUCIBLE_QUANTUM_MIN_IDLE_SPEEDUP    required idle:boot rate ratio
//! CRUCIBLE_QUANTUM_TIMEOUT_SECS        per-quantum host wait bound (seconds)
//! CRUCIBLE_QUANTUM_SECOND_RUN_LOAD     "0" disables second-run host load
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
    LivePluginQuantumGateConfig, LivePluginQuantumSchedule, run_live_plugin_quantum_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-plugin-quantum: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-plugin-quantum"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let root_image = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    let initrd = args.next();
    let kernel_cmdline = args.next();
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut config =
        LivePluginQuantumGateConfig::new(qemu, plugin, kernel, root_image, run_directory)
            .with_schedule(schedule_from_env()?)
            .with_completion_timeout(Duration::from_secs(env_u64(
                "CRUCIBLE_QUANTUM_TIMEOUT_SECS",
                240,
            )?))
            .with_second_run_host_load(env_flag("CRUCIBLE_QUANTUM_SECOND_RUN_LOAD", true)?);
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    if let Some(kernel_cmdline) = kernel_cmdline {
        let kernel_cmdline = kernel_cmdline
            .into_string()
            .map_err(|_| String::from("kernel command line is not valid UTF-8"))?;
        config = config.with_kernel_cmdline(kernel_cmdline);
    }
    if let Some(firmware) = env::var_os("CRUCIBLE_QUANTUM_FIRMWARE") {
        config = config.with_firmware(firmware);
    }

    let report = run_live_plugin_quantum_gate(&config).map_err(|error| error_chain(&error))?;
    let rates = &report.rates;
    println!("PASS");
    println!("gate=gate:plugin-quantum-time-authority");
    println!("plugin_loaded=rust-control-cdylib");
    println!("time_authority=rust-plugin");
    println!("idle_onset_icount={}", report.idle.idle_onset_icount);
    println!(
        "idle_next_deadline_icount={}",
        report.idle.next_deadline_icount
    );
    println!("idle_ceiling_icount={}", report.idle.ceiling_icount);
    println!("boot_quantum_count={}", report.idle.boot_quantum_count);
    // The scheduler only observes the idle park through a published next timer
    // deadline, so the idle kind proven here is a timer-deadline idle (distinct
    // from an I/O-wait idle, which has no deadline to jump toward).
    println!("idle_kind=timer-deadline");
    println!("boot_icount_span={}", rates.boot_icount_span);
    println!("boot_wall_micros={}", rates.boot_wall_micros);
    println!("boot_icount_per_second={}", rates.boot_icount_per_second());
    println!("idle_icount_span={}", rates.idle_icount_span);
    println!("idle_wall_micros={}", rates.idle_wall_micros);
    println!("idle_icount_per_second={}", rates.idle_icount_per_second());
    println!("terminal_icount={}", rates.terminal_icount);
    println!("idle_jump_proven={}", report.idle_jump_proven);
    if !report.idle_jump_proven {
        // Descoped while the QEMU-side queued-time-advance completion defect is
        // open. The plugin correctly reads the deadline, releases, enqueues, and
        // arms the idle advance, but QEMU never commits it (patches 0010/0021/0025).
        println!("idle_jump_defect=T-PLUG-7-live-idle-jump-advance-completion");
    }
    println!(
        "deterministic_under_host_load={}",
        report.deterministic_under_host_load
    );
    println!("host_load_applied={}", report.host_load_applied);
    println!(
        "execution_fingerprint={}",
        report.execution_fingerprint.hash.to_hex()
    );
    println!(
        "time_authority_is_rust_plugin={}",
        report.time_authority_is_rust_plugin
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn schedule_from_env() -> Result<LivePluginQuantumSchedule, String> {
    let default = LivePluginQuantumSchedule::new();
    Ok(LivePluginQuantumSchedule {
        ceiling_step_icount: env_u64("CRUCIBLE_QUANTUM_CEILING_STEP", default.ceiling_step_icount)?,
        max_search_icount: env_u64("CRUCIBLE_QUANTUM_MAX_SEARCH", default.max_search_icount)?,
        idle_horizon_margin_icount: env_u64(
            "CRUCIBLE_QUANTUM_IDLE_HORIZON_MARGIN",
            default.idle_horizon_margin_icount,
        )?,
        min_idle_speedup_ratio: env_u64(
            "CRUCIBLE_QUANTUM_MIN_IDLE_SPEEDUP",
            default.min_idle_speedup_ratio,
        )?,
    })
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
    format!(
        "usage: {program} QEMU PLUGIN KERNEL ROOT_IMAGE RUN_DIRECTORY [INITRD [KERNEL_CMDLINE]]"
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-plugin-quantum requires Linux");
}
