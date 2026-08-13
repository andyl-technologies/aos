//! Applies a signal-driven lifecycle fault to one real patched-QEMU process.
//!
//! Positional arguments are `QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY` and an
//! optional `INITRD`. The machine-readable report is consumed by the hermetic
//! live gate.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error as _;
#[cfg(target_os = "linux")]
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use crucible_qemu::{QemuLiveNodeStepGateConfig, run_qemu_live_node_lifecycle_fault_gate};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-node-lifecycle-fault: {error}");
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
        .unwrap_or_else(|| String::from("crucible-qemu-live-node-lifecycle-fault"));
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
        .with_second_run_host_load(false);
    if let Some(initrd) = initrd {
        config = config.with_initrd(initrd);
    }
    let report = run_qemu_live_node_lifecycle_fault_gate(&config).map_err(|error| {
        let mut diagnostic = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            diagnostic.push_str(": ");
            diagnostic.push_str(&cause.to_string());
            source = cause.source();
        }
        diagnostic
    })?;
    if !report.lifecycle_impulse_committed {
        return Err(String::from(
            "the signal runtime did not commit exactly one lifecycle impulse",
        ));
    }

    println!("PASS");
    println!("gate=gate:live-node-lifecycle-fault");
    println!("backend=production-qemu-signal-runtime");
    println!("effect=node.lifecycle");
    println!("transition=crash");
    println!("observed_icount={}", report.observed_icount);
    println!("action={}", report.action.to_hex());
    println!("evidence={}", report.evidence.to_hex());
    println!("exit_code={}", report.exit_code);
    println!(
        "lifecycle_impulse_committed={}",
        report.lifecycle_impulse_committed
    );
    println!(
        "exact_manifest_replay_admitted={}",
        report.exact_manifest_replay_admitted
    );
    println!(
        "changed_state_precondition_rejected={}",
        report.changed_state_precondition_rejected
    );
    println!(
        "corrupt_result_rejected_with_valid_event={}",
        report.corrupt_result_rejected_with_valid_event
    );
    println!(
        "corrupt_event_rejected_with_valid_result={}",
        report.corrupt_event_rejected_with_valid_result
    );
    println!(
        "cross_adapter_actions_committed={}",
        report.cross_adapter_actions_committed
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
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-node-lifecycle-fault requires Linux");
}
