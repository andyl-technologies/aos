//! Runs the first live [`QemuNode`] bounded-step gate.
//!
//! Boots the diskless-firmware guest once with the Rust control plugin and a QMP
//! endpoint, assembles a real scheduler-facing `QemuNode` over the production
//! host-I/O runtime, and advances it through a busy-window ceiling schedule using
//! the public `QemuNode::advance_to_ceiling` API. The whole run is repeated -- the
//! second time under bounded scheduler preemption -- and the two runs must be byte-identical.
//!
//! Prints machine-checkable evidence the phase2 gate asserts: per-step
//! raw-versus-logical accounting (every busy-window boundary's logical offset is
//! zero), the terminal execution fingerprint, cross-run determinism, and an
//! orderly child exit.
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]`.
//! Scheduler tuning is read from the environment so the gate can be tuned on a
//! builder without rebuilding:
//!
//! ```text
//! CRUCIBLE_NODE_STEP_CEILING_STEP   busy-window ceiling increment (icount)
//! CRUCIBLE_NODE_STEP_COUNT          number of bounded steps to drive
//! CRUCIBLE_NODE_STEP_BUSY_CAP       exclusive busy-window icount cap
//! CRUCIBLE_NODE_STEP_TIMEOUT_SECS   per-step host wait bound (seconds)
//! CRUCIBLE_NODE_STEP_SECOND_RUN_SCHEDULER_PREEMPTION "0" disables second-run bounded scheduler preemption
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
    QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig, QemuLiveNodeStepSchedule,
    run_qemu_live_node_step_gate,
};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-node-step: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-node-step"));
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
        .with_fingerprint(QemuLaunchPluginSwitch::On)
        .with_schedule(schedule_from_env()?)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_NODE_STEP_TIMEOUT_SECS",
            240,
        )?))
        .with_second_run_scheduler_preemption(env_flag(
            "CRUCIBLE_NODE_STEP_SECOND_RUN_SCHEDULER_PREEMPTION",
            true,
        )?);
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }

    let report = run_qemu_live_node_step_gate(&config).map_err(|error| error_chain(&error))?;

    println!("PASS");
    println!("gate=gate:live-node-step");
    println!("plugin_loaded=rust-control-cdylib");
    println!("node_kind=live-qemu-node");
    println!("host_io_runtime=qemu-live-host-io-runtime");
    println!("qmp_channel=vmstate-exact-snapshot");
    println!("quantum_count={}", report.quanta.len());
    for (index, step) in report.quanta.iter().enumerate() {
        // Raw-versus-logical accounting: target is the raw scheduler ceiling,
        // completion is the node's logical published icount, and the offset must
        // be zero at every busy-window boundary (no idle-jump offset leaked in).
        println!(
            "quantum_step[{index}] target={} completion={} logical_offset={} reissue_count={} reached_horizon={}",
            step.target_icount,
            step.completion_icount,
            step.logical_offset,
            step.reissue_count,
            step.reached_horizon
        );
    }
    println!(
        "busy_window_logical_offset_zero={}",
        report.busy_window_logical_offset_zero
    );
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
        "execution_fingerprint={}",
        report.execution_fingerprint.hash.to_hex()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn schedule_from_env() -> Result<QemuLiveNodeStepSchedule, String> {
    let default = QemuLiveNodeStepSchedule::new();
    let step_count = env_u64("CRUCIBLE_NODE_STEP_COUNT", u64::from(default.step_count))?;
    let step_count = u32::try_from(step_count)
        .map_err(|_| String::from("CRUCIBLE_NODE_STEP_COUNT exceeds the u32 range"))?;
    Ok(QemuLiveNodeStepSchedule {
        ceiling_step_icount: env_u64(
            "CRUCIBLE_NODE_STEP_CEILING_STEP",
            default.ceiling_step_icount,
        )?,
        step_count,
        busy_cap_icount: env_u64("CRUCIBLE_NODE_STEP_BUSY_CAP", default.busy_cap_icount)?,
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
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-node-step requires Linux");
}
