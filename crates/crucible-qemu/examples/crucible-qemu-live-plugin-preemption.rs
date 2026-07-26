//! Runs the production loaded-QEMU scheduler-commanded preemption gate.

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
    LivePluginQuantumGateConfig, LivePluginQuantumSchedule, run_live_plugin_preemption_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-plugin-preemption: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-plugin-preemption"));
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

    let ceiling_step_icount = env_u64("CRUCIBLE_PREEMPTION_CEILING_STEP", 4_000_000)?;
    let mut config =
        LivePluginQuantumGateConfig::new(qemu, plugin, kernel, root_image, run_directory)
            .with_schedule(LivePluginQuantumSchedule {
                ceiling_step_icount,
                max_search_icount: ceiling_step_icount.saturating_mul(3),
                idle_horizon_margin_icount: 0,
                min_idle_speedup_ratio: 1,
            })
            .with_rr_switch_quantum(env_u64("CRUCIBLE_PREEMPTION_RR_SWITCH_QUANTUM", 4096)?)
            .with_completion_timeout(Duration::from_secs(env_u64(
                "CRUCIBLE_PREEMPTION_TIMEOUT_SECS",
                240,
            )?))
            .with_second_run_host_load(env_flag("CRUCIBLE_PREEMPTION_SECOND_RUN_LOAD", true)?);
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    if let Some(kernel_cmdline) = kernel_cmdline {
        config = config.with_kernel_cmdline(
            kernel_cmdline
                .into_string()
                .map_err(|_| String::from("kernel command line is not valid UTF-8"))?,
        );
    }
    if let Some(firmware) = env::var_os("CRUCIBLE_PREEMPTION_FIRMWARE") {
        config = config.with_firmware(firmware);
    }

    let report = run_live_plugin_preemption_gate(&config).map_err(|error| error_chain(&error))?;
    println!("PASS");
    println!("gate=gate:live-plugin-preemption");
    println!("smp_vcpus=2");
    println!("switch_icount={}", report.switch_icount);
    println!("switch_from_vcpu={}", report.switch_from_vcpu);
    println!("switch_to_vcpu={}", report.switch_to_vcpu);
    println!(
        "switch_consumed_sequence={}",
        report.switch_consumed_sequence
    );
    println!("interrupt_icount={}", report.interrupt_icount);
    println!("ipi_send_icount={}", report.ipi_send_icount);
    println!(
        "ipi_fixed_latency_icount={}",
        report.ipi_fixed_latency_icount
    );
    println!(
        "ipi_earliest_delivery_icount={}",
        report.ipi_earliest_delivery_icount
    );
    println!("ipi_rr_switch_quantum={}", report.ipi_rr_switch_quantum);
    println!("interrupt_sender_vcpu={}", report.interrupt_sender_vcpu);
    println!("interrupt_target_vcpu={}", report.interrupt_target_vcpu);
    println!("interrupt_vector={}", report.interrupt_vector);
    println!(
        "interrupt_consumed_sequence={}",
        report.interrupt_consumed_sequence
    );
    println!("terminal_icount={}", report.terminal_icount);
    println!(
        "deterministic_under_host_load={}",
        report.deterministic_under_host_load
    );
    println!("host_load_applied={}", report.host_load_applied);
    println!(
        "sim_double_schedule_matches={}",
        report.sim_double_schedule_matches
    );
    println!(
        "execution_fingerprint={}",
        report.execution_fingerprint.hash.to_hex()
    );
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
    format!(
        "usage: {program} QEMU PLUGIN KERNEL ROOT_IMAGE RUN_DIRECTORY [INITRD] [KERNEL_CMDLINE]"
    )
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
fn error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        message.push_str(": ");
        message.push_str(&error.to_string());
        source = error.source();
    }
    message
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-plugin-preemption requires Linux");
}
